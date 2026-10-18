"""JS/TS agent and MCP tools, with the operations their parameters reach.

Recognized definitions:

* MCP server registrations - ``server.tool(name, ..., handler)`` and
  ``server.registerTool(name, config, handler)`` in a module that imports
  ``@modelcontextprotocol/sdk``;
* tool constructors - ``tool({ execute })`` from ``ai`` (Vercel AI SDK) or
  ``@openai/agents``, bound to a variable or an object property.

The capability proof is shared with the prompt-flow detector, so a tool is
only capable of what a parameter of its own executor provably reaches.
"""

from __future__ import annotations

from collections.abc import Iterable

from aibom.detectors.base import ScanContext
from aibom.detectors.javascript.nodes import (
    CallExpr,
    FunctionNode,
    Identifier,
    MemberExpr,
    Node,
    ObjectExpr,
    VarDecl,
    walk,
)
from aibom.detectors.javascript.parser import JsModule
from aibom.detectors.javascript.prompt_flow import (
    BoundTool,
    _capabilities_in,
    _executor_parameters,
    _prop,
    _resolve_anywhere,
    _static_value,
)
from aibom.detectors.project import ProjectIndex, js_returns
from aibom.detectors.result import Detection
from aibom.models.analysis import ConfidenceFactors, UsageState, ValueResolution
from aibom.models.entities import Tool
from aibom.models.evidence import Evidence

_MCP_MODULE = "@modelcontextprotocol/sdk"
_MCP_REGISTRARS = frozenset({"tool", "registerTool"})
_TOOL_FACTORIES = {"ai.tool": "vercel-ai", "@openai/agents.tool": "openai-agents"}
_SUPPORTED_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


class ToolCapabilityJavaScriptDetector:
    detector_id = "javascript.tool-capability.ast"

    def supports(self, path: str) -> bool:
        lowered = path.lower()
        if lowered.endswith((".d.ts", ".min.js")):
            return False
        return lowered.endswith(_SUPPORTED_SUFFIXES)

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = context.javascript
        if module is None:
            return
        project = context.project
        if module.has_import(_MCP_MODULE):
            for call in module.calls:
                registration = _mcp_registration(project, module, call)
                if registration is not None:
                    name, handler = registration
                    yield Detection(self._tool(context, call, name, "mcp", handler))
        for node, name, call in _constructed_tools(module):
            framework = _TOOL_FACTORIES[module.qualified_name(call.callee) or ""]
            executor = _executor(project, module, call)
            yield Detection(self._tool(context, node, name, framework, executor))

    def _tool(
        self,
        context: ScanContext,
        node: Node,
        name: str,
        framework: str,
        handler: tuple[JsModule, FunctionNode] | None,
    ) -> Tool:
        module = context.javascript
        assert module is not None
        registered = framework == "mcp"
        capabilities = []
        if handler is not None:
            owner, function = handler
            tool = BoundTool(name=name, execute=function, module=owner)
            controlled = {item: {item} for item in _executor_parameters(function)}
            capabilities = _capabilities_in(
                tool, owner, function, controlled, self.detector_id, context.project, [], set()
            )
        state = "registered" if registered else "declared"
        if registered and handler is None:
            state = "unknown"
        return Tool(
            name=f"{name}@{context.relative_path}",
            tool_name=name,
            framework=framework,
            state=state,
            trust_boundary="tool_caller_to_application" if registered else None,
            capabilities=capabilities,
            source_evidence=[
                Evidence(
                    file=context.relative_path,
                    line_start=node.line,
                    line_end=node.end_line,
                    column_start=node.column,
                    snippet=f"<{framework} tool:{name}>",
                    matched_pattern=f"tool-definition:{framework}",
                    confidence=0.95,
                    detector_id=self.detector_id,
                    kind="ast",
                )
            ],
            detector_ids=[self.detector_id],
            usage=UsageState(declared=True, instantiated=registered),
            confidence_factors=ConfidenceFactors(
                syntax_confidence=1.0,
                value_resolution_confidence=1.0 if handler is not None else 0.5,
                framework_identification_confidence=0.95,
            ),
            source_contexts=[context.source_context],
            value_resolution=(
                ValueResolution.RESOLVED if handler is not None else ValueResolution.UNRESOLVED
            ),
        )


def _mcp_registration(
    project: ProjectIndex | None, module: JsModule, call: CallExpr
) -> tuple[str, tuple[JsModule, FunctionNode] | None] | None:
    callee = call.callee
    if (
        not isinstance(callee, MemberExpr)
        or callee.computed
        or not isinstance(callee.prop, Identifier)
        or callee.prop.name not in _MCP_REGISTRARS
        or len(call.args) < 2
    ):
        return None
    name = _static_value(module, call.args[0])
    if not isinstance(name, str) or not name:
        return None
    owner, handler = _resolve_anywhere(project, module, call.args[-1])
    if isinstance(handler, FunctionNode):
        return name, (owner, handler)
    return name, None


def _constructed_tools(module: JsModule) -> Iterable[tuple[Node, str, CallExpr]]:
    """``const x = tool({...})`` and ``{ x: tool({...}) }`` with their names."""
    seen: set[int] = set()
    for node in walk(module.program):
        if isinstance(node, VarDecl) and isinstance(node.init, FunctionNode):
            # A tool factory: `const createX = (deps) => tool({...})`.
            returns = js_returns(node.init)
            if (
                len(returns) == 1
                and isinstance(returns[0], CallExpr)
                and _is_factory(module, returns[0])
                and id(returns[0]) not in seen
            ):
                seen.add(id(returns[0]))
                yield node, _declared_name(module, returns[0]) or node.name, returns[0]
        elif isinstance(node, VarDecl) and isinstance(node.init, CallExpr):
            if _is_factory(module, node.init) and id(node.init) not in seen:
                seen.add(id(node.init))
                yield node, _declared_name(module, node.init) or node.name, node.init
        elif isinstance(node, ObjectExpr):
            for prop in node.properties:
                value = prop.value
                if (
                    prop.key
                    and isinstance(value, CallExpr)
                    and _is_factory(module, value)
                    and id(value) not in seen
                ):
                    seen.add(id(value))
                    yield value, _declared_name(module, value) or prop.key, value


def _is_factory(module: JsModule, call: CallExpr) -> bool:
    return (module.qualified_name(call.callee) or "") in _TOOL_FACTORIES


def _declared_name(module: JsModule, call: CallExpr) -> str | None:
    for argument in call.args:
        if isinstance(argument, ObjectExpr):
            value = _static_value(module, _prop(argument, "name"))
            if isinstance(value, str) and value:
                return value
    return None


def _executor(
    project: ProjectIndex | None, module: JsModule, call: CallExpr
) -> tuple[JsModule, FunctionNode] | None:
    for argument in call.args:
        owner, options = _resolve_anywhere(project, module, argument)
        if not isinstance(options, ObjectExpr):
            continue
        for key in ("execute", "handler", "func", "run"):
            target_owner, target = _resolve_anywhere(project, owner, _prop(options, key))
            if isinstance(target, FunctionNode):
                return target_owner, target
    return None
