"""Bounded Python prompt source-to-sink analysis.

The detector recognizes provider-specific prompt sinks and follows simple
same-file assignments and expression composition back to external input
sources.  It never imports or executes repository code, and it never stores
prompt text in evidence or resolution paths.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass

from aibom.detectors.base import ScanContext
from aibom.detectors.flow import (
    FlowTrace,
    SourceRef,
    Span,
    capability_evidence,
    combine_traces,
    content_hash,
    flow_step,
    sink_evidence,
    source_evidence,
)
from aibom.detectors.python.common import argument_node, require_python
from aibom.detectors.python.parser import PythonModule
from aibom.detectors.python.value_resolver import ValueResolver
from aibom.detectors.result import Detection
from aibom.models.analysis import (
    ConfidenceFactors,
    Reachability,
    ResolutionStep,
    UsageState,
    ValueResolution,
)
from aibom.models.entities import Prompt, ToolCapability

_MAX_DEPTH = 20
_OPENAI_SUFFIXES = (
    ".responses.create",
    ".chat.completions.create",
    ".completions.create",
    ".beta.assistants.create",
)
_ANTHROPIC_SUFFIXES = (
    ".messages.create",
    ".messages.stream",
    ".completions.create",
)
_OPENAI_AGENT_CONSTRUCTORS = {"agents.Agent"}
_UNTRUSTED_ENTRYPOINTS = {
    "http_route": ("http_parameter", "network_to_application"),
    "cli": ("cli_argument", "local_user_to_application"),
    "mcp_tool": ("tool_input", "tool_caller_to_application"),
    "lambda": ("event_input", "event_source_to_application"),
}


def _span(node: ast.AST) -> Span:
    """Reduce a Python AST node to the position the shared analysis uses."""
    line = getattr(node, "lineno", 1)
    return Span(
        line=line,
        end_line=getattr(node, "end_lineno", line) or line,
        column=getattr(node, "col_offset", 0) + 1,
    )


@dataclass(frozen=True)
class PromptInput:
    expression: ast.AST
    kind: str
    name: str
    sink_kind: str


class PromptFlowPythonDetector:
    """Detect prompt sinks and emit sanitized, auditable data-flow metadata."""

    detector_id = "python.prompt-flow.ast"

    def supports(self, path: str) -> bool:
        return path.lower().endswith(".py")

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = require_python(context)
        resolver = ValueResolver(module)
        for call in module.calls:
            provider = _provider_for_call(module, call)
            if provider is None:
                continue
            model_refs = _model_refs(call, resolver)
            tool_refs = _bound_tool_refs(module, call)
            capabilities = _bound_tool_capabilities(
                context,
                module,
                tool_refs,
                self.detector_id,
            )
            for prompt_input in _prompt_inputs(module, call, provider, resolver):
                yield Detection(
                    self._entity(
                        context,
                        module,
                        call,
                        prompt_input,
                        resolver,
                        model_refs,
                        tool_refs,
                        capabilities,
                    )
                )

    def _entity(
        self,
        context: ScanContext,
        module: PythonModule,
        call: ast.Call,
        prompt_input: PromptInput,
        resolver: ValueResolver,
        model_refs: list[str],
        tool_refs: list[str],
        capabilities: list[ToolCapability],
    ) -> Prompt:
        expression = prompt_input.expression
        resolved = resolver.resolve(expression)
        trace = _FlowTracer(module).trace(expression)
        reachable, reachability_path = module.reachability(call)

        hashed = (
            content_hash(resolved.value)
            if resolved.resolved and not trace.sources
            else None
        )
        value_resolution = (
            ValueResolution.RESOLVED if resolved.resolved else ValueResolution.UNRESOLVED
        )
        source = trace.sources[0] if trace.sources else None
        evidence = [
            sink_evidence(
                context.relative_path, _span(call), self.detector_id, prompt_input.sink_kind
            )
        ]
        evidence.extend(
            source_evidence(context.relative_path, item, self.detector_id)
            for item in trace.sources
        )
        sink_step = flow_step(
            context.relative_path, _span(call), prompt_input.sink_kind, "prompt_sink"
        )
        resolution_path = [
            item.model_copy(update={"value": None}) for item in resolved.steps
        ]

        return Prompt(
            name=prompt_input.name,
            kind=prompt_input.kind,
            content_hash=hashed,
            source_kind=source.kind if source else None,
            sink_kind=prompt_input.sink_kind,
            trust_boundary=source.trust_boundary if source else None,
            user_controlled=trace.user_controlled,
            model_refs=model_refs,
            tool_refs=tool_refs,
            capabilities=[item.model_copy(deep=True) for item in capabilities],
            data_flow_path=[*trace.steps, sink_step],
            source_evidence=evidence,
            detector_ids=[self.detector_id],
            usage=UsageState(
                declared=True,
                imported=True,
                instantiated=True,
                invoked=True,
                reachable=reachable,
            ),
            confidence_factors=ConfidenceFactors(
                syntax_confidence=1.0,
                value_resolution_confidence=(resolved.confidence if resolved.resolved else 0.55),
                framework_identification_confidence=1.0,
                reachability_confidence=(0.85 if reachable is not Reachability.UNKNOWN else 0.25),
            ),
            resolution_path=resolution_path,
            reachability_path=reachability_path,
            source_contexts=[context.source_context],
            value_resolution=value_resolution,
        )


class _FlowTracer:
    """Conservative same-file expression tracer with a strict depth bound."""

    def __init__(self, module: PythonModule) -> None:
        self.module = module

    def trace(self, node: ast.AST) -> FlowTrace:
        return self._trace(node, set(), 0)

    def _trace(
        self,
        node: ast.AST,
        seen: set[tuple[str | None, str]],
        depth: int,
    ) -> FlowTrace:
        if depth > _MAX_DEPTH:
            return FlowTrace(None, steps=(self._step(node, None, "max_depth"),))

        if isinstance(node, ast.Constant):
            return FlowTrace(False)

        if isinstance(node, ast.Name):
            source = self._parameter_source(node)
            if source is not None:
                return self._source(node, *source)
            named = _named_source(node.id)
            if named is not None:
                return self._source(node, *named)
            key = (self.module.scope_for(node), node.id)
            if key in seen:
                return FlowTrace(None, steps=(self._step(node, node.id, "cycle"),))
            assignment = self.module.assignment_for(node.id, node)
            if assignment is None:
                return FlowTrace(
                    None,
                    steps=(self._step(node, node.id, "unknown_symbol"),),
                )
            traced = self._trace(assignment.value, {*seen, key}, depth + 1)
            return FlowTrace(
                traced.user_controlled,
                traced.sources,
                (
                    *traced.steps,
                    self._step(assignment.value, node.id, "variable_reference"),
                ),
            )

        if isinstance(node, ast.Attribute):
            qualified = self.module.qualified_name(node) or node.attr
            source = _named_source(qualified)
            if source is not None:
                return self._source(node, *source)
            return self._trace(node.value, seen, depth + 1)

        if isinstance(node, ast.Subscript):
            qualified = self.module.qualified_name(node.value) or ""
            source = _named_source(qualified)
            if source is not None:
                return self._source(node, *source)
            return combine_traces(
                self._trace(node.value, seen, depth + 1),
                self._trace(node.slice, seen, depth + 1),
            )

        if isinstance(node, ast.Call):
            qualified = self.module.qualified_name(node.func) or ""
            source = _call_source(qualified)
            if source is not None:
                return self._source(node, *source)
            children = [*node.args, *(kw.value for kw in node.keywords)]
            return combine_traces(*(self._trace(child, seen, depth + 1) for child in children))

        if isinstance(node, ast.JoinedStr):
            return combine_traces(*(self._trace(value, seen, depth + 1) for value in node.values))

        if isinstance(node, ast.FormattedValue):
            return self._trace(node.value, seen, depth + 1)

        if isinstance(node, ast.Dict):
            return combine_traces(*(self._trace(value, seen, depth + 1) for value in node.values))

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return combine_traces(*(self._trace(value, seen, depth + 1) for value in node.elts))

        if isinstance(node, ast.BinOp):
            return combine_traces(
                self._trace(node.left, seen, depth + 1),
                self._trace(node.right, seen, depth + 1),
            )

        if isinstance(node, ast.IfExp):
            return combine_traces(
                self._trace(node.body, seen, depth + 1),
                self._trace(node.orelse, seen, depth + 1),
            )

        return FlowTrace(None, steps=(self._step(node, None, "dynamic_expression"),))

    def _parameter_source(
        self, node: ast.Name
    ) -> tuple[str, str, str, bool | None] | None:
        function = self.module.enclosing_function(node)
        if function is None or function.entrypoint_kind not in _UNTRUSTED_ENTRYPOINTS:
            return None
        args = function.node.args
        parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg is not None:
            parameters.append(args.vararg)
        if args.kwarg is not None:
            parameters.append(args.kwarg)
        if node.id not in {parameter.arg for parameter in parameters}:
            return None
        kind, boundary = _UNTRUSTED_ENTRYPOINTS[function.entrypoint_kind]
        return kind, node.id, boundary, True

    def _source(
        self,
        node: ast.AST,
        kind: str,
        symbol: str,
        boundary: str,
        user_controlled: bool | None,
    ) -> FlowTrace:
        source = SourceRef(kind, _span(node), symbol, boundary)
        return FlowTrace(
            user_controlled,
            (source,),
            (self._step(node, symbol, f"source:{kind}"),),
        )

    def _step(self, node: ast.AST, symbol: str | None, operation: str) -> ResolutionStep:
        return flow_step(self.module.relative_path, _span(node), symbol, operation)


def _provider_for_call(module: PythonModule, call: ast.Call) -> str | None:
    qualified = module.qualified_name(call.func) or ""
    if module.has_import("agents") and qualified in _OPENAI_AGENT_CONSTRUCTORS:
        return "openai-agents"
    if module.has_import("openai", "langchain_openai") and qualified.endswith(
        _OPENAI_SUFFIXES
    ):
        return "openai"
    if module.has_import("anthropic", "langchain_anthropic") and qualified.endswith(
        _ANTHROPIC_SUFFIXES
    ):
        return "anthropic"
    return None


def _prompt_inputs(
    module: PythonModule,
    call: ast.Call,
    provider: str,
    resolver: ValueResolver,
) -> list[PromptInput]:
    qualified = module.qualified_name(call.func) or ""
    rel = module.relative_path

    if provider == "openai-agents" and qualified in _OPENAI_AGENT_CONSTRUCTORS:
        expression = argument_node(call, ("instructions",))
        if expression is None:
            return []
        return [
            PromptInput(
                expression,
                "system",
                f"agent-instructions@{rel}:{getattr(expression, 'lineno', call.lineno)}",
                "openai.agents.Agent.instructions",
            )
        ]

    if qualified.endswith(".beta.assistants.create"):
        expression = argument_node(call, ("instructions",))
        if expression is None:
            return []
        return [
            PromptInput(
                expression,
                "system",
                f"assistant-instructions@{rel}:{call.lineno}",
                "openai.beta.assistants.create.instructions",
            )
        ]

    if qualified.endswith(".responses.create"):
        found: list[PromptInput] = []
        instructions = argument_node(call, ("instructions",))
        if instructions is not None:
            found.append(
                PromptInput(
                    instructions,
                    "system",
                    f"system-prompt@{rel}:{getattr(instructions, 'lineno', call.lineno)}",
                    "openai.responses.create.instructions",
                )
            )
        response_input = argument_node(call, ("input",))
        if response_input is not None:
            kind = _expression_kind(response_input, "user")
            found.append(
                PromptInput(
                    response_input,
                    kind,
                    f"{kind}-prompt@{rel}:{getattr(response_input, 'lineno', call.lineno)}",
                    "openai.responses.create.input",
                )
            )
        return found

    if qualified.endswith(".chat.completions.create") or qualified.endswith(
        ".messages.create"
    ) or qualified.endswith(".messages.stream"):
        system = argument_node(call, ("system",))
        messages = argument_node(call, ("messages",))
        found = []
        if system is not None:
            found.append(
                PromptInput(
                    system,
                    "system",
                    f"system-prompt@{rel}:{getattr(system, 'lineno', call.lineno)}",
                    f"{provider}.messages.system",
                )
            )
        if messages is not None:
            split = _split_messages(module, messages, provider, resolver)
            if split:
                found.extend(split)
            else:
                kind = _expression_kind(messages, "template")
                found.append(
                    PromptInput(
                        messages,
                        kind,
                        f"{kind}-prompt@{rel}:{getattr(messages, 'lineno', call.lineno)}",
                        f"{provider}.messages",
                    )
                )
        return found

    if qualified.endswith(".completions.create"):
        expression = argument_node(call, ("prompt",), positional=0)
        if expression is None:
            return []
        kind = _expression_kind(expression, "user")
        return [
            PromptInput(
                expression,
                kind,
                f"{kind}-prompt@{rel}:{getattr(expression, 'lineno', call.lineno)}",
                f"{provider}.completions.create.prompt",
            )
        ]
    return []


def _split_messages(
    module: PythonModule,
    expression: ast.AST,
    provider: str,
    resolver: ValueResolver,
) -> list[PromptInput]:
    sequence = _dereference_sequence(module, expression, set(), 0)
    if sequence is None:
        return []
    found: list[PromptInput] = []
    for index, item in enumerate(sequence.elts):
        if not isinstance(item, ast.Dict):
            return []
        role_node = _dict_value(item, "role")
        content = _dict_value(item, "content")
        if content is None:
            return []
        role_result = resolver.resolve(role_node) if role_node is not None else None
        role = (
            str(role_result.value).lower()
            if role_result is not None
            and role_result.resolved
            and isinstance(role_result.value, str)
            else "unknown"
        )
        kind = role if role in {"system", "developer", "user", "assistant"} else "template"
        line = getattr(item, "lineno", getattr(content, "lineno", 1))
        suffix = "" if kind in {"system", "developer"} else f":{index}"
        found.append(
            PromptInput(
                content,
                kind,
                f"{kind}-prompt@{module.relative_path}:{line}{suffix}",
                f"{provider}.messages.{kind}.content",
            )
        )
    return found


def _dereference_sequence(
    module: PythonModule,
    expression: ast.AST,
    seen: set[tuple[str | None, str]],
    depth: int,
) -> ast.List | ast.Tuple | None:
    if depth > _MAX_DEPTH:
        return None
    if isinstance(expression, (ast.List, ast.Tuple)):
        return expression
    if not isinstance(expression, ast.Name):
        return None
    key = (module.scope_for(expression), expression.id)
    if key in seen:
        return None
    assignment = module.assignment_for(expression.id, expression)
    if assignment is None:
        return None
    return _dereference_sequence(module, assignment.value, {*seen, key}, depth + 1)


def _dict_value(node: ast.Dict, key: str) -> ast.AST | None:
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if isinstance(key_node, ast.Constant) and key_node.value == key:
            return value_node
    return None


def _expression_kind(expression: ast.AST, default: str) -> str:
    if isinstance(expression, ast.Name):
        lowered = expression.id.lower()
        if "system" in lowered or "instruction" in lowered or "developer" in lowered:
            return "system"
    return default


def _model_refs(call: ast.Call, resolver: ValueResolver) -> list[str]:
    expression = argument_node(call, ("model", "model_name"))
    if expression is None:
        return []
    resolved = resolver.resolve(expression)
    if not resolved.resolved or not isinstance(resolved.value, str):
        return []
    value = resolved.value.strip()
    lowered = value.lower()
    sensitive_marker = any(
        marker in lowered
        for marker in ("password", "api_key", "api-key", "secret", "bearer ")
    )
    opaque_secret = len(value) >= 48 and value.isalnum()
    if (
        not value
        or len(value) > 160
        or lowered.startswith("sk-")
        or sensitive_marker
        or opaque_secret
    ):
        return []
    return [value]


def _bound_tool_refs(module: PythonModule, call: ast.Call) -> list[str]:
    """Return explicit tool names from an agent constructor's ``tools`` list."""
    expression = argument_node(call, ("tools",))
    if expression is None:
        return []
    sequence = _dereference_sequence(module, expression, set(), 0)
    if sequence is None:
        return []
    names: list[str] = []
    for item in sequence.elts:
        qualified = module.qualified_name(item)
        if qualified is None:
            return []
        name = qualified.rsplit(".", 1)[-1]
        if name not in names:
            names.append(name)
    return names


def _bound_tool_capabilities(
    context: ScanContext,
    module: PythonModule,
    tool_refs: list[str],
    detector_id: str,
) -> list[ToolCapability]:
    """Classify high-impact calls only inside explicitly bound decorated tools."""
    found: list[ToolCapability] = []
    for tool_name in tool_refs:
        functions = [
            info for info in module.functions.values() if info.name == tool_name
        ]
        if len(functions) != 1 or not _is_recognized_tool(module, functions[0].node):
            continue
        function = functions[0].node
        parameters = _function_parameters(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            qualified = module.qualified_name(node.func) or ""
            classified = _classify_capability(qualified, node)
            if classified is None:
                continue
            controlled = sorted(
                parameter
                for parameter in parameters
                if _call_uses_parameter(module, node, parameter, set(), 0)
            )
            if not controlled:
                continue
            kind, impact, severity = classified
            evidence = capability_evidence(
                context.relative_path,
                _span(node),
                detector_id,
                tool_name=tool_name,
                kind=kind,
                operation=qualified,
            )
            found.append(
                ToolCapability(
                    tool_name=tool_name,
                    kind=kind,
                    operation=qualified,
                    impact=impact,
                    severity=severity,
                    controlled_parameters=controlled,
                    source_evidence=[evidence],
                )
            )
    return found


def _is_recognized_tool(
    module: PythonModule,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        qualified = module.qualified_name(target) or ""
        if qualified == "agents.function_tool":
            return True
        if qualified in {
            "langchain_core.tools.tool",
            "langchain.tools.tool",
            "mcp.tool",
            "fastmcp.tool",
        }:
            return True
        if qualified.endswith(".tool") and module.has_import("mcp", "fastmcp"):
            return True
    return False


def _classify_capability(
    qualified: str,
    call: ast.Call,
) -> tuple[str, str, str] | None:
    lowered = qualified.lower()
    if lowered in {
        "subprocess.run",
        "subprocess.popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }:
        return ("command_execution", "execute operating-system commands", "critical")
    if lowered in {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
        "pathlib.path.unlink",
        "pathlib.path.rmdir",
        "unlink",
        "rmdir",
    }:
        return ("destructive_filesystem", "delete files or directories", "high")
    if lowered in {
        "pathlib.path.write_text",
        "pathlib.path.write_bytes",
        "write_text",
        "write_bytes",
    } or (lowered in {"open", "builtins.open"} and _open_can_write(call)):
        return ("filesystem_write", "write or overwrite local files", "medium")
    if lowered.endswith((".sendmail", ".send_message")) and any(
        marker in lowered for marker in ("smtp", "mail", "email")
    ):
        return ("external_action", "send messages to an external recipient", "high")
    if lowered in {
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "urllib.request.urlopen",
    }:
        return ("network_egress", "send data or state-changing requests off host", "medium")
    return None


def _open_can_write(call: ast.Call) -> bool:
    mode: ast.AST | None = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
            break
    return (
        isinstance(mode, ast.Constant)
        and isinstance(mode.value, str)
        and any(flag in mode.value for flag in ("w", "a", "x", "+"))
    )


def _function_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    args = node.args
    parameters = {
        item.arg for item in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    }
    if args.vararg is not None:
        parameters.add(args.vararg.arg)
    if args.kwarg is not None:
        parameters.add(args.kwarg.arg)
    return parameters


def _call_uses_parameter(
    module: PythonModule,
    call: ast.Call,
    parameter: str,
    seen: set[tuple[str | None, str]],
    depth: int,
) -> bool:
    expressions: list[ast.AST] = [*call.args, *(item.value for item in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        expressions.append(call.func.value)
    return any(
        _expression_uses_parameter(module, item, parameter, seen, depth)
        for item in expressions
    )


def _expression_uses_parameter(
    module: PythonModule,
    node: ast.AST,
    parameter: str,
    seen: set[tuple[str | None, str]],
    depth: int,
) -> bool:
    if depth > _MAX_DEPTH:
        return False
    if isinstance(node, ast.Name):
        if node.id == parameter:
            return True
        key = (module.scope_for(node), node.id)
        if key in seen:
            return False
        assignment = module.assignment_for(node.id, node)
        return (
            assignment is not None
            and _expression_uses_parameter(
                module,
                assignment.value,
                parameter,
                {*seen, key},
                depth + 1,
            )
        )
    return any(
        _expression_uses_parameter(module, child, parameter, seen, depth + 1)
        for child in ast.iter_child_nodes(node)
    )


def _named_source(name: str) -> tuple[str, str, str, bool | None] | None:
    lowered = name.lower()
    if lowered == "sys.argv" or lowered.startswith("sys.argv"):
        return "cli_argument", name, "local_user_to_application", True
    if "websocket" in lowered:
        return "websocket_message", name, "network_to_application", True
    request_markers = (
        "request.",
        ".request.",
    )
    if lowered == "request" or any(marker in lowered for marker in request_markers):
        return "http_request", name, "network_to_application", True
    if any(marker in lowered for marker in ("retrieved_doc", "retrieved_context", "rag_context")):
        return "retrieved_document", name, "retrieval_to_prompt", None
    return None


def _call_source(name: str) -> tuple[str, str, str, bool | None] | None:
    lowered = name.lower()
    if lowered in {"input", "builtins.input"}:
        return "cli_argument", name, "local_user_to_application", True
    if lowered in {"os.getenv", "os.environ.get"}:
        return "environment", name, "environment_to_application", None
    named = _named_source(name)
    if named is not None:
        return named
    if lowered.endswith((".read", ".read_text", ".read_bytes")):
        return "file", name, "filesystem_to_application", None
    if any(marker in lowered for marker in ("retriever.invoke", "similarity_search", ".retrieve")):
        return "retrieved_document", name, "retrieval_to_prompt", None
    if lowered.endswith((".fetchone", ".fetchall")):
        return "database", name, "database_to_application", None
    return None
