"""Bounded JavaScript/TypeScript prompt source-to-sink and capability analysis.

This is the TypeScript counterpart of
:mod:`aibom.detectors.python.prompt_flow`.  It recognizes provider-specific
prompt sinks (Vercel AI SDK, OpenAI Agents, OpenAI and Anthropic Node SDKs),
follows same-file bindings back to untrusted sources, and classifies
high-impact operations inside explicitly bound agent tools.

It never imports, bundles, transpiles, or executes the analyzed code, and it
never retains prompt text or tool argument values.
"""

from __future__ import annotations

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
from aibom.detectors.javascript.nodes import (
    ArrayExpr,
    AssignExpr,
    AwaitExpr,
    BinaryExpr,
    CallExpr,
    ConditionalExpr,
    FunctionNode,
    Identifier,
    Literal,
    MemberExpr,
    Node,
    ObjectExpr,
    Param,
    SpreadExpr,
    TemplateLiteral,
    UnaryExpr,
    children,
    walk,
)
from aibom.detectors.javascript.parser import JsFunctionInfo, JsModule
from aibom.detectors.project import (
    MAX_CALL_DEPTH,
    MAX_CALL_SITES,
    Budget,
    ProjectIndex,
    js_returns,
)
from aibom.detectors.result import Detection
from aibom.models.analysis import (
    ConfidenceFactors,
    Reachability,
    ResolutionStep,
    UsageState,
    ValueResolution,
)
from aibom.models.entities import Prompt, ToolCapability
from aibom.models.evidence import Evidence

_MAX_DEPTH = 20
_MAX_HELPER_DEPTH = 3
_SUPPORTED_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

# Vercel AI SDK core entrypoints; all take a single options object.
_AI_SDK_CALLS = frozenset(
    {"generateText", "streamText", "generateObject", "streamObject"}
)
# `parse` and `stream` (also under `beta.`) take the same prompt arguments.
_RESPONSES_SUFFIXES = (".responses.create", ".responses.parse", ".responses.stream")
_CHAT_SUFFIXES = (
    ".chat.completions.create",
    ".chat.completions.parse",
    ".chat.completions.stream",
)
_OPENAI_SUFFIXES = (
    *_RESPONSES_SUFFIXES,
    *_CHAT_SUFFIXES,
    ".completions.create",
    ".beta.assistants.create",
    # Assistants API: a thread message is a prompt the next run sends.
    ".beta.threads.messages.create",
)
_ANTHROPIC_SUFFIXES = (".messages.create", ".messages.stream")

_OPENAI_MODULES = ("openai", "@ai-sdk/openai", "@langchain/openai")
_ANTHROPIC_MODULES = ("@anthropic-ai/sdk", "@ai-sdk/anthropic", "@langchain/anthropic")

_UNTRUSTED_ENTRYPOINTS = {
    "http_route": ("http_request", "network_to_application"),
    "mcp_tool": ("tool_input", "tool_caller_to_application"),
    "lambda": ("event_input", "event_source_to_application"),
    "cli": ("cli_argument", "local_user_to_application"),
}

_PRIVILEGED_ROLES = {"system", "developer"}


def _span(node: Node) -> Span:
    """Reduce a JS/TS node to the language-agnostic position the analysis uses."""
    return Span(line=node.line, end_line=node.end_line, column=node.column)


@dataclass(frozen=True)
class PromptInput:
    expression: Node
    kind: str
    name: str
    sink_kind: str


@dataclass(frozen=True)
class BoundTool:
    name: str
    execute: FunctionNode
    #: module defining the executor (differs from the agent's for imported tools)
    module: JsModule


class PromptFlowJavaScriptDetector:
    """Detect JS/TS prompt sinks and their bound agent capabilities."""

    detector_id = "javascript.prompt-flow.ast"

    def supports(self, path: str) -> bool:
        lowered = path.lower()
        if lowered.endswith((".d.ts", ".min.js")):
            return False
        return lowered.endswith(_SUPPORTED_SUFFIXES)

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = context.javascript
        if module is None:
            return
        for call in module.calls:
            provider = _provider_for_call(module, call, context.project)
            if provider is None:
                continue
            options = _options_object(module, call)
            model_refs = _model_refs(module, options)
            tools = _bound_tools(context.project, module, options)
            capabilities = _tool_capabilities(tools, self.detector_id, context.project)
            for prompt_input in _prompt_inputs(module, call, provider, options):
                yield Detection(
                    self._entity(
                        context,
                        module,
                        call,
                        prompt_input,
                        model_refs,
                        [tool.name for tool in tools],
                        capabilities,
                    )
                )

    def _entity(
        self,
        context: ScanContext,
        module: JsModule,
        call: CallExpr,
        prompt_input: PromptInput,
        model_refs: list[str],
        tool_refs: list[str],
        capabilities: list[ToolCapability],
    ) -> Prompt:
        expression = prompt_input.expression
        trace = _FlowTracer(module, context.project).trace(expression)
        static_value = _static_value(module, expression)
        reachable, reachability_path = _reachability(module, call, context.project)

        hashed = (
            content_hash(static_value)
            if static_value is not None and not trace.sources
            else None
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
                value_resolution_confidence=(0.95 if static_value is not None else 0.55),
                framework_identification_confidence=1.0,
                reachability_confidence=(
                    0.85 if reachable is not Reachability.UNKNOWN else 0.25
                ),
            ),
            reachability_path=reachability_path,
            source_contexts=[context.source_context],
            value_resolution=(
                ValueResolution.RESOLVED
                if static_value is not None
                else ValueResolution.UNRESOLVED
            ),
        )


# ---------------------------------------------------------------------------
# Sink identification
# ---------------------------------------------------------------------------


def _provider_for_call(
    module: JsModule, call: CallExpr, project: ProjectIndex | None = None
) -> str | None:
    qualified = module.qualified_name(call.callee) or ""
    local = module.local_name(call.callee) or ""

    if (
        call.is_new
        and module.has_import("@openai/agents")
        and local.rsplit(".", 1)[-1] in {"Agent", "RealtimeAgent"}
    ):
        return "openai-agents"
    imported = _imported_client_provider(project, module, call.callee)
    if imported == "openai" and qualified.endswith(_OPENAI_SUFFIXES):
        return "openai"
    if imported == "anthropic" and qualified.endswith(_ANTHROPIC_SUFFIXES):
        return "anthropic"
    if (
        module.has_import("ai")
        and qualified.startswith("ai.")
        and qualified.rsplit(".", 1)[-1] in _AI_SDK_CALLS
    ):
        return "vercel-ai"
    if module.has_import(*_OPENAI_MODULES) and qualified.endswith(_OPENAI_SUFFIXES):
        return "openai"
    if module.has_import(*_ANTHROPIC_MODULES) and qualified.endswith(_ANTHROPIC_SUFFIXES):
        return "anthropic"
    return None


def _imported_client_provider(
    project: ProjectIndex | None, module: JsModule, callee: Node
) -> str | None:
    """Provider of an SDK client created in another module (``new OpenAI()``)."""
    if project is None:
        return None
    root = callee
    while isinstance(root, MemberExpr):
        root = root.obj
    if not isinstance(root, Identifier) or root.name not in module.aliases:
        return None
    symbol = project.js_symbol(module, root.name)
    value = symbol.value if symbol is not None else None
    if isinstance(value, AwaitExpr):
        value = value.argument
    if symbol is None or not isinstance(value, CallExpr) or not value.is_new:
        return None
    constructor = symbol.module.qualified_name(value.callee) or ""
    if constructor.startswith(_OPENAI_MODULES):
        return "openai"
    if constructor.startswith(_ANTHROPIC_MODULES):
        return "anthropic"
    return None


def _options_object(module: JsModule, call: CallExpr) -> ObjectExpr | None:
    """Every supported sink takes its configuration as one object argument."""
    for argument in call.args:
        resolved = _resolve(module, argument)
        if isinstance(resolved, ObjectExpr):
            return resolved
    return None


def _prompt_inputs(
    module: JsModule,
    call: CallExpr,
    provider: str,
    options: ObjectExpr | None,
) -> list[PromptInput]:
    if options is None:
        return []
    rel = module.relative_path
    found: list[PromptInput] = []

    def add(node: Node | None, kind: str, sink: str, *, suffix: str = "") -> None:
        if node is None:
            return
        found.append(
            PromptInput(node, kind, f"{kind}-prompt@{rel}:{node.line}{suffix}", sink)
        )

    if provider == "openai-agents":
        add(_prop(options, "instructions"), "system", "openai.agents.Agent.instructions")
        return found

    if provider == "vercel-ai":
        family = (module.qualified_name(call.callee) or "").rsplit(".", 1)[-1]
        # The AI SDK renamed the privileged slot from `system` to `instructions`
        # in v5; both still appear in the wild, and both are privileged.
        add(_prop(options, "system"), "system", f"ai.{family}.system")
        add(_prop(options, "instructions"), "system", f"ai.{family}.instructions")
        add(_prop(options, "prompt"), "user", f"ai.{family}.prompt")
        found.extend(
            _split_messages(module, _prop(options, "messages"), f"ai.{family}.messages")
        )
        return found

    if provider == "openai":
        qualified = module.qualified_name(call.callee) or ""
        if qualified.endswith(".beta.threads.messages.create"):
            role = _static_value(module, _prop(options, "role"))
            kind = role if role in {"user", "assistant"} else "template"
            add(_prop(options, "content"), str(kind), "openai.beta.threads.messages.content")
            return found
        if qualified.endswith(".beta.assistants.create"):
            add(
                _prop(options, "instructions"),
                "system",
                "openai.beta.assistants.create.instructions",
            )
            return found
        if qualified.endswith(_RESPONSES_SUFFIXES):
            add(
                _prop(options, "instructions"),
                "system",
                "openai.responses.create.instructions",
            )
            add(_prop(options, "input"), "user", "openai.responses.create.input")
            if not found:
                # A proxy that forwards `{ ...body }`: the prompt is whatever the
                # spread carries - a real sink with unresolved content.
                add(_spread(options), "template", "openai.responses.create.input")
            return found
        found.extend(
            _split_messages(module, _prop(options, "messages"), "openai.messages")
        )
        if not found:
            add(_spread(options), "template", "openai.messages")
        return found

    if provider == "anthropic":
        add(_prop(options, "system"), "system", "anthropic.messages.system")
        found.extend(
            _split_messages(module, _prop(options, "messages"), "anthropic.messages")
        )
    return found


def _split_messages(
    module: JsModule, expression: Node | None, sink_prefix: str
) -> list[PromptInput]:
    """Separate a messages array into role-specific prompt inputs."""
    array = _resolve(module, expression) if expression is not None else None
    if not isinstance(array, ArrayExpr):
        if expression is None:
            return []
        return [
            PromptInput(
                expression,
                "template",
                f"template-prompt@{module.relative_path}:{expression.line}",
                sink_prefix,
            )
        ]
    found: list[PromptInput] = []
    for index, element in enumerate(array.elements):
        item = _resolve(module, element)
        if not isinstance(item, ObjectExpr):
            continue
        content = _prop(item, "content")
        if content is None:
            continue
        role_node = _prop(item, "role")
        role = _static_value(module, role_node) if role_node is not None else None
        role_name = str(role).lower() if isinstance(role, str) else "unknown"
        kind = (
            role_name
            if role_name in {"system", "developer", "user", "assistant"}
            else "template"
        )
        suffix = "" if kind in _PRIVILEGED_ROLES else f":{index}"
        found.append(
            PromptInput(
                content,
                kind,
                f"{kind}-prompt@{module.relative_path}:{content.line}{suffix}",
                f"{sink_prefix}.{kind}.content",
            )
        )
    return found


def _model_refs(module: JsModule, options: ObjectExpr | None) -> list[str]:
    """Resolve the model identifier from `model:` in the options object."""
    if options is None:
        return []
    node = _prop(options, "model") or _prop(options, "modelName")
    if node is None:
        return []
    resolved = _resolve(module, node)
    value: object | None = None
    if isinstance(resolved, CallExpr):
        # Provider factories: openai('gpt-4.1'), anthropic('claude-...').
        for argument in resolved.args:
            candidate = _static_value(module, argument)
            if isinstance(candidate, str):
                value = candidate
                break
    else:
        value = _static_value(module, resolved)
    if not isinstance(value, str):
        return []
    return [value] if _plausible_model_name(value) else []


def _plausible_model_name(value: str) -> bool:
    """Reject secrets and prose that happen to sit in a `model:` slot."""
    text = value.strip()
    lowered = text.lower()
    if not text or len(text) > 160:
        return False
    if lowered.startswith("sk-") or (len(text) >= 48 and text.isalnum()):
        return False
    return not any(
        marker in lowered
        for marker in ("password", "api_key", "api-key", "secret", "bearer ")
    )


# ---------------------------------------------------------------------------
# Tool bindings and capabilities
# ---------------------------------------------------------------------------


def _bound_tools(
    project: ProjectIndex | None, module: JsModule, options: ObjectExpr | None
) -> list[BoundTool]:
    """Return tools explicitly bound by this call, with their executors.

    Only direct bindings count: an object map (Vercel AI SDK) or an array of
    tool bindings (OpenAI Agents).  A helper that merely sits in the same file
    is never promoted to a bound tool.  A binding may name a tool defined in
    another module (``tools: { shell: shellTool }`` with ``shellTool``
    imported); the executor is then analyzed in that module.
    """
    if options is None:
        return []
    owner, node = _resolve_anywhere(project, module, _prop(options, "tools"))
    found: list[BoundTool] = []
    if isinstance(node, ObjectExpr):
        for prop in node.properties:
            if prop.key is None:
                continue
            located = _tool_executor(project, owner, prop.value)
            if located is not None:
                found.append(BoundTool(name=prop.key, execute=located[1], module=located[0]))
    elif isinstance(node, ArrayExpr):
        for element in node.elements:
            located = _tool_executor(project, owner, element)
            if located is None:
                continue
            name = _tool_name(project, owner, element) or (
                element.name if isinstance(element, Identifier) else "tool"
            )
            found.append(BoundTool(name=name, execute=located[1], module=located[0]))
    return found


def _tool_definition(
    project: ProjectIndex | None, module: JsModule, node: Node
) -> tuple[JsModule, CallExpr] | None:
    """The ``tool({...})`` call a binding refers to, possibly in another module.

    A factory (``tools: { shell: createShellTool() }``) is followed one level
    into its return value when the index resolves the factory.
    """
    owner, resolved = _resolve_anywhere(project, module, node)
    if not isinstance(resolved, CallExpr):
        return None
    if project is not None:
        target = project.js_function(owner, resolved.callee)
        if target is not None:
            returns = js_returns(target[1].node)
            if len(returns) == 1:
                inner_owner, inner = _resolve_anywhere(project, target[0], returns[0])
                if isinstance(inner, CallExpr):
                    return inner_owner, inner
            return None
    return owner, resolved


def _tool_executor(
    project: ProjectIndex | None, module: JsModule, node: Node
) -> tuple[JsModule, FunctionNode] | None:
    """Find the function a tool binding will run when the model calls it."""
    definition = _tool_definition(project, module, node)
    if definition is None:
        return None
    owner, call = definition
    for argument in call.args:
        options_owner, options = _resolve_anywhere(project, owner, argument)
        if not isinstance(options, ObjectExpr):
            continue
        for key in ("execute", "handler", "func", "run"):
            candidate_owner, candidate = _resolve_anywhere(
                project, options_owner, _prop(options, key)
            )
            if isinstance(candidate, FunctionNode):
                return candidate_owner, candidate
    return None


def _tool_name(project: ProjectIndex | None, module: JsModule, node: Node) -> str | None:
    definition = _tool_definition(project, module, node)
    if definition is None:
        return None
    owner, call = definition
    for argument in call.args:
        options = _resolve(owner, argument)
        if isinstance(options, ObjectExpr):
            value = _static_value(owner, _prop(options, "name"))
            if isinstance(value, str) and value:
                return value
    return None


def _tool_capabilities(
    tools: list[BoundTool],
    detector_id: str,
    project: ProjectIndex | None,
) -> list[ToolCapability]:
    """Classify high-impact operations reachable from a bound tool's parameters.

    The executor body is searched first; calls into project helpers that
    receive a tool parameter are followed (bounded), so an operation in
    ``lib/tools/run.ts`` reached from an executor in ``lib/tools/index.ts`` is
    still attributed to the tool, with both locations as evidence.
    """
    found: list[ToolCapability] = []
    for tool in tools:
        parameters = _executor_parameters(tool.execute)
        if not parameters:
            continue
        controlled = {parameter: {parameter} for parameter in parameters}
        found.extend(
            _capabilities_in(
                tool, tool.module, tool.execute, controlled, detector_id, project, [], set()
            )
        )
    return found


def _capabilities_in(
    tool: BoundTool,
    module: JsModule,
    function: FunctionNode,
    controlled: dict[str, set[str]],
    detector_id: str,
    project: ProjectIndex | None,
    chain: list[Evidence],
    visited: set[tuple[str, int]],
) -> list[ToolCapability]:
    key = (module.relative_path, id(function))
    if key in visited or len(chain) >= _MAX_HELPER_DEPTH:
        return []
    visited = {*visited, key}
    found: list[ToolCapability] = []
    for node in walk(function):
        if not isinstance(node, CallExpr):
            continue
        qualified = module.qualified_name(node.callee) or ""
        classified = _classify_capability(module, node, qualified)
        if classified is not None:
            reached = sorted(
                {
                    tool_parameter
                    for local, tool_parameters in controlled.items()
                    if _call_uses_parameter(module, node, local, set(), 0)
                    for tool_parameter in tool_parameters
                }
            )
            if not reached:
                continue
            kind, impact, severity = classified
            found.append(
                ToolCapability(
                    tool_name=tool.name,
                    kind=kind,
                    operation=qualified or "eval",
                    impact=impact,
                    severity=severity,
                    controlled_parameters=reached,
                    source_evidence=[
                        *(item.model_copy() for item in chain),
                        capability_evidence(
                            module.relative_path,
                            _span(node),
                            detector_id,
                            tool_name=tool.name,
                            kind=kind,
                            operation=qualified,
                        ),
                    ],
                )
            )
            continue
        if project is None:
            continue
        helper = project.js_function(module, node.callee)
        if helper is None:
            continue
        helper_module, helper_info = helper
        mapped: dict[str, set[str]] = {}
        for param in helper_info.params:
            argument = _argument_for(node, param)
            if argument is None:
                continue
            reached_by = {
                tool_parameter
                for local, tool_parameters in controlled.items()
                if _expression_uses_parameter(module, argument, local, set(), 0)
                for tool_parameter in tool_parameters
            }
            if reached_by and param.name:
                mapped[param.name] = reached_by
        if not mapped:
            continue
        hop = capability_evidence(
            module.relative_path,
            _span(node),
            detector_id,
            tool_name=tool.name,
            kind="helper_call",
            operation=helper_info.name,
        )
        hop.matched_pattern = f"bound-tool-helper:{helper_info.name}"
        found.extend(
            _capabilities_in(
                tool,
                helper_module,
                helper_info.node,
                mapped,
                detector_id,
                project,
                [*chain, hop],
                visited,
            )
        )
    return found


def _argument_for(call: CallExpr, param: Param) -> Node | None:
    """The argument ``call`` passes to ``param``; a destructured name picks its property."""
    if param.index >= len(call.args):
        return None
    argument = call.args[param.index]
    if isinstance(argument, SpreadExpr) or any(
        isinstance(item, SpreadExpr) for item in call.args[: param.index]
    ):
        return None
    if param.properties and isinstance(argument, ObjectExpr):
        for prop in argument.properties:
            if prop.key == param.name:
                return prop.value
        return None
    return argument


def _executor_parameters(execute: FunctionNode) -> set[str]:
    """Model-controlled bindings: the tool executor's own parameter names."""
    return {param.name for param in execute.params if param.name}


_COMMAND_MODULES = frozenset({"child_process"})
_COMMAND_FUNCTIONS = frozenset(
    {
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "spawn",
        "spawnSync",
        "fork",
    }
)
_VM_MODULES = frozenset({"vm", "node:vm"})
_VM_FUNCTIONS = frozenset(
    {"runInNewContext", "runInThisContext", "runInContext", "compileFunction"}
)
_FS_MODULES = frozenset({"fs", "fs/promises"})
_FS_DELETE_FUNCTIONS = frozenset(
    {"rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"}
)
_FS_WRITE_FUNCTIONS = frozenset(
    {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "createWriteStream",
        "copyFile",
        "copyFileSync",
    }
)
_HTTP_CLIENT_METHODS = frozenset({"post", "put", "patch", "delete", "request"})
_MAIL_METHODS = frozenset({"sendMail", "sendEmail", "send"})


def _classify_capability(
    module: JsModule, call: CallExpr, qualified: str
) -> tuple[str, str, str] | None:
    """Map a call to (kind, consequence, severity), or None when benign."""
    module_part, _, function = qualified.rpartition(".")
    module_part = module_part.removeprefix("node:")

    if module_part in _COMMAND_MODULES and function in _COMMAND_FUNCTIONS:
        return ("command_execution", "execute operating-system commands", "critical")
    if module_part.removeprefix("node:") in _VM_MODULES and function in _VM_FUNCTIONS:
        return ("command_execution", "evaluate attacker-supplied code", "critical")
    if not module_part and function in {"eval", "Function"}:
        return ("command_execution", "evaluate attacker-supplied code", "critical")
    if module_part in _FS_MODULES and function in _FS_DELETE_FUNCTIONS:
        return ("destructive_filesystem", "delete files or directories", "high")
    if module_part in _FS_MODULES and function in _FS_WRITE_FUNCTIONS:
        return ("filesystem_write", "write or overwrite local files", "medium")
    if function in _MAIL_METHODS and _looks_like_mailer(module, call):
        return ("external_action", "send messages to an external recipient", "high")
    if module_part == "axios" and function in _HTTP_CLIENT_METHODS:
        return ("network_egress", "send data or state-changing requests off host", "medium")
    if not module_part and function == "fetch" and _fetch_is_state_changing(module, call):
        return ("network_egress", "send data or state-changing requests off host", "medium")
    return None


def _looks_like_mailer(module: JsModule, call: CallExpr) -> bool:
    base = (module.local_name(call.callee) or "").lower()
    return any(marker in base for marker in ("mail", "smtp", "transport", "postmark"))


def _fetch_is_state_changing(module: JsModule, call: CallExpr) -> bool:
    """A bare GET fetch is not treated as egress; an explicit write method is."""
    for argument in call.args:
        options = _resolve(module, argument)
        if not isinstance(options, ObjectExpr):
            continue
        method = _static_value(module, _prop(options, "method"))
        if isinstance(method, str) and method.upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            return True
    return False


def _call_uses_parameter(
    module: JsModule,
    call: CallExpr,
    parameter: str,
    seen: set[tuple[str | None, str]],
    depth: int,
) -> bool:
    expressions: list[Node] = list(call.args)
    if isinstance(call.callee, MemberExpr):
        expressions.append(call.callee.obj)
    return any(
        _expression_uses_parameter(module, item, parameter, seen, depth)
        for item in expressions
    )


def _expression_uses_parameter(
    module: JsModule,
    node: Node,
    parameter: str,
    seen: set[tuple[str | None, str]],
    depth: int,
) -> bool:
    if depth > _MAX_DEPTH:
        return False
    if isinstance(node, Identifier):
        if node.name == parameter:
            return True
        key = (module.scope_for(node), node.name)
        if key in seen:
            return False
        assignment = module.assignment_for(node.name, node)
        return assignment is not None and _expression_uses_parameter(
            module, assignment.value, parameter, {*seen, key}, depth + 1
        )
    return any(
        _expression_uses_parameter(module, child, parameter, seen, depth + 1)
        for child in children(node)
    )


# ---------------------------------------------------------------------------
# Flow tracing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Frame:
    """One resolved call the tracer descended into: params bind to ``call``'s args."""

    module_path: str
    function: str
    caller: _FlowTracer
    call: CallExpr


# Result is a plain transformation of the inputs: tainted input stays a
# *proven* flow.  Any other call the index cannot resolve makes it potential.
_TRANSPARENT_CALLS = frozenset({"String", "JSON.stringify", "encodeURIComponent"})
_TRANSPARENT_METHODS = frozenset(
    {
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "toString",
        "join",
        "concat",
        "replace",
        "replaceAll",
        "slice",
        "substring",
        "split",
        "padStart",
        "padEnd",
    }
)

_SeenKey = tuple[str, str | None, str]


class _FlowTracer:
    """Conservative expression tracer, bounded in depth, call depth, and visits.

    The TypeScript counterpart of the Python tracer: within a file it follows
    bindings and composition; with a :class:`ProjectIndex` it also follows a
    parameter to its resolved call sites (``call_argument``), a call into a
    project function through its returns (``call_return``), and an imported
    binding to its definition (``import_reference``).
    """

    def __init__(
        self,
        module: JsModule,
        project: ProjectIndex | None = None,
        *,
        budget: Budget | None = None,
        frames: tuple[_Frame, ...] = (),
        ascent: int = 0,
    ) -> None:
        self.module = module
        self.project = project
        self.budget = budget or Budget()
        self.frames = frames
        self.ascent = ascent

    def trace(self, node: Node) -> FlowTrace:
        return self._trace(node, set(), 0)

    def _spawn(
        self,
        module: JsModule,
        *,
        frames: tuple[_Frame, ...] | None = None,
        ascent: int | None = None,
    ) -> _FlowTracer:
        return _FlowTracer(
            module,
            self.project,
            budget=self.budget,
            frames=self.frames if frames is None else frames,
            ascent=self.ascent if ascent is None else ascent,
        )

    def _trace(self, node: Node, seen: set[_SeenKey], depth: int) -> FlowTrace:
        if depth > _MAX_DEPTH:
            return FlowTrace(None, steps=(self._step(node, None, "max_depth"),))
        if not self.budget.spend():
            return FlowTrace(None, steps=(self._step(node, None, "analysis_budget_exhausted"),))

        if isinstance(node, Literal):
            return FlowTrace(False)

        if isinstance(node, Identifier):
            source = self._parameter_source(node)
            if source is not None:
                return self._source(node, *source)
            named = _named_source(node.name)
            if named is not None:
                return self._source(node, *named)
            key = (self.module.relative_path, self.module.scope_for(node), node.name)
            if key in seen:
                return FlowTrace(None, steps=(self._step(node, node.name, "cycle"),))
            assignment = self.module.assignment_for(node.name, node)
            if assignment is None:
                crossed = self._parameter_flow(node, {*seen, key}, depth)
                if crossed is None:
                    crossed = self._import_flow(node, {*seen, key}, depth)
                if crossed is not None:
                    return crossed
                return FlowTrace(
                    None, steps=(self._step(node, node.name, "unknown_symbol"),)
                )
            traced = self._trace(assignment.value, {*seen, key}, depth + 1)
            return FlowTrace(
                traced.user_controlled,
                traced.sources,
                (
                    *traced.steps,
                    self._step(assignment.value, node.name, "variable_reference"),
                ),
            )

        if isinstance(node, MemberExpr):
            local = self.module.local_name(node) or ""
            source = _named_source(local) or self._member_parameter_source(node, local)
            if source is not None:
                return self._source(node, *source)
            traced = self._trace(node.obj, seen, depth + 1)
            if node.computed:
                return combine_traces(traced, self._trace(node.prop, seen, depth + 1))
            return traced

        if isinstance(node, CallExpr):
            qualified = self.module.qualified_name(node.callee) or ""
            local = self.module.local_name(node.callee) or ""
            source = _call_source(qualified) or _call_source(local)
            if source is not None:
                return self._source(node, *source)
            summarized = self._call_summary(node, seen, depth)
            if summarized is not None:
                return summarized
            traces = [self._trace(argument, seen, depth + 1) for argument in node.args]
            if isinstance(node.callee, MemberExpr):
                traces.append(self._trace(node.callee, seen, depth + 1))
            traced = combine_traces(*traces)
            if traced.user_controlled is True and not _transparent_call(node, local):
                return _with_step(traced, self._step(node, local or None, "unresolved_call"))
            return traced

        if isinstance(node, TemplateLiteral):
            return combine_traces(
                *(self._trace(item, seen, depth + 1) for item in node.expressions)
            )

        if isinstance(node, BinaryExpr):
            return combine_traces(
                self._trace(node.left, seen, depth + 1),
                self._trace(node.right, seen, depth + 1),
            )

        if isinstance(node, ObjectExpr):
            return combine_traces(
                *(self._trace(prop.value, seen, depth + 1) for prop in node.properties)
            )

        if isinstance(node, ArrayExpr):
            return combine_traces(
                *(self._trace(item, seen, depth + 1) for item in node.elements)
            )

        if isinstance(node, ConditionalExpr):
            return combine_traces(
                self._trace(node.consequent, seen, depth + 1),
                self._trace(node.alternate, seen, depth + 1),
            )

        if isinstance(node, (AwaitExpr, SpreadExpr, UnaryExpr)):
            return self._trace(node.argument, seen, depth + 1)

        if isinstance(node, AssignExpr):
            return self._trace(node.value, seen, depth + 1)

        return FlowTrace(None, steps=(self._step(node, None, "dynamic_expression"),))

    # -- interprocedural ----------------------------------------------------

    def _declaring_function(self, node: Identifier) -> tuple[JsFunctionInfo, Param] | None:
        info = self.module.enclosing_function(node)
        while info is not None:
            for param in info.params:
                if param.name == node.name:
                    return info, param
            info = self._parent_function(info.qualified_name)
        return None

    def _parameter_flow(
        self, node: Identifier, seen: set[_SeenKey], depth: int
    ) -> FlowTrace | None:
        """Bind a parameter of an ordinary function to its call-site arguments."""
        declared = self._declaring_function(node)
        if declared is None:
            return None
        function, param = declared
        for frame in reversed(self.frames):
            if (
                frame.module_path == self.module.relative_path
                and frame.function == function.qualified_name
            ):
                argument = _argument_for(frame.call, param)
                if argument is None:
                    return FlowTrace(
                        None, steps=(self._step(node, node.name, "unbound_parameter"),)
                    )
                traced = frame.caller._trace(argument, seen, depth + 1)
                return _with_step(traced, frame.caller._step(argument, node.name, "call_argument"))
        if self.project is None or self.ascent >= MAX_CALL_DEPTH:
            return None
        callers = self.project.js_callers(self.module, function)
        if not callers:
            return None
        traces: list[FlowTrace] = []
        for caller_module, call in callers[:MAX_CALL_SITES]:
            argument = _argument_for(call, param)
            if argument is None:
                traces.append(FlowTrace(None))
                continue
            caller = self._spawn(caller_module, frames=(), ascent=self.ascent + 1)
            traced = caller._trace(argument, seen, depth + 1)
            traces.append(_with_step(traced, caller._step(argument, node.name, "call_argument")))
        if len(callers) > MAX_CALL_SITES:
            traces.append(
                FlowTrace(None, steps=(self._step(node, node.name, "analysis_budget_exhausted"),))
            )
        return combine_traces(*traces)

    def _call_summary(
        self, node: CallExpr, seen: set[_SeenKey], depth: int
    ) -> FlowTrace | None:
        """Trace a call into a project function through its return values."""
        if self.project is None or len(self.frames) >= MAX_CALL_DEPTH:
            return None
        target = self.project.js_function(self.module, node.callee)
        if target is None:
            return None
        target_module, info = target
        if any(
            frame.module_path == target_module.relative_path
            and frame.function == info.qualified_name
            for frame in self.frames
        ):
            return FlowTrace(None, steps=(self._step(node, info.name, "cycle"),))
        returns = js_returns(info.node)
        if not returns:
            return FlowTrace(False)
        frame = _Frame(target_module.relative_path, info.qualified_name, self, node)
        callee = self._spawn(target_module, frames=(*self.frames, frame))
        traced = combine_traces(
            *(
                _with_step(
                    callee._trace(item, seen, depth + 1),
                    callee._step(item, info.name, "return_value"),
                )
                for item in returns
            )
        )
        return _with_step(traced, self._step(node, info.name, "call_return"))

    def _import_flow(
        self, node: Identifier, seen: set[_SeenKey], depth: int
    ) -> FlowTrace | None:
        """Follow an imported binding into the module that defines it."""
        if self.project is None or node.name not in self.module.aliases:
            return None
        symbol = self.project.js_symbol(self.module, node.name)
        if symbol is None or symbol.value is None or isinstance(symbol.value, FunctionNode):
            return None
        target = self._spawn(symbol.module)
        traced = target._trace(symbol.value, seen, depth + 1)
        return _with_step(traced, target._step(symbol.value, node.name, "import_reference"))

    # -- sources ------------------------------------------------------------

    def _parameter_source(
        self, node: Identifier
    ) -> tuple[str, str, str, bool | None] | None:
        info = self.module.enclosing_function(node)
        while info is not None:
            if info.entrypoint_kind in _UNTRUSTED_ENTRYPOINTS and any(
                param.name == node.name for param in info.params
            ):
                kind, boundary = _UNTRUSTED_ENTRYPOINTS[info.entrypoint_kind]
                return kind, node.name, boundary, True
            info = self._parent_function(info.qualified_name)
        return None

    def _member_parameter_source(
        self, node: MemberExpr, local: str
    ) -> tuple[str, str, str, bool | None] | None:
        """`request.body` where `request` is an entrypoint parameter."""
        root = local.split(".")[0] if local else ""
        if not root:
            return None
        base = node
        while isinstance(base, MemberExpr):
            base = base.obj  # type: ignore[assignment]
        if not isinstance(base, Identifier):
            return None
        return self._parameter_source(base)

    def _parent_function(self, qualified: str) -> JsFunctionInfo | None:
        if "." not in qualified:
            return None
        return self.module.functions.get(qualified.rsplit(".", 1)[0])

    def _source(
        self,
        node: Node,
        kind: str,
        symbol: str,
        boundary: str,
        user_controlled: bool | None,
    ) -> FlowTrace:
        source = SourceRef(kind, _span(node), symbol, boundary, self.module.relative_path)
        return FlowTrace(
            user_controlled,
            (source,),
            (self._step(node, symbol, f"source:{kind}"),),
        )

    def _step(self, node: Node, symbol: str | None, operation: str) -> ResolutionStep:
        return flow_step(self.module.relative_path, _span(node), symbol, operation)


def _with_step(trace: FlowTrace, step: ResolutionStep) -> FlowTrace:
    return FlowTrace(trace.user_controlled, trace.sources, (*trace.steps, step))


def _transparent_call(node: CallExpr, local: str) -> bool:
    if local in _TRANSPARENT_CALLS:
        return True
    callee = node.callee
    return (
        isinstance(callee, MemberExpr)
        and isinstance(callee.prop, Identifier)
        and callee.prop.name in _TRANSPARENT_METHODS
    )


def _named_source(name: str) -> tuple[str, str, str, bool | None] | None:
    """Classify a dotted expression that is itself an untrusted origin."""
    lowered = name.lower()
    if not lowered:
        return None
    if lowered.startswith("process.argv"):
        return "cli_argument", name, "local_user_to_application", True
    if lowered.startswith("process.env"):
        return "environment", name, "environment_to_application", None
    root = lowered.split(".")[0]
    tail = lowered.rsplit(".", 1)[-1]
    if root in {"req", "request", "ctx", "context", "event"} and tail in {
        "body",
        "query",
        "params",
        "headers",
        "cookies",
        "rawbody",
        "searchparams",
        "url",
    }:
        return "http_request", name, "network_to_application", True
    if "searchparams" in lowered or "nexturl" in lowered:
        return "http_request", name, "network_to_application", True
    if "websocket" in lowered:
        return "websocket_message", name, "network_to_application", True
    if any(
        marker in lowered
        for marker in ("retrieveddoc", "retrievedcontext", "ragcontext", "retrieved_")
    ):
        return "retrieved_document", name, "retrieval_to_prompt", None
    return None


def _call_source(name: str) -> tuple[str, str, str, bool | None] | None:
    """Classify a call whose *result* is untrusted input."""
    lowered = name.lower()
    if not lowered:
        return None
    tail = lowered.rsplit(".", 1)[-1]
    root = lowered.split(".")[0]
    if root in {"req", "request", "ctx", "context"} and tail in {
        "json",
        "text",
        "formdata",
        "arraybuffer",
        "blob",
    }:
        return "http_request", name, "network_to_application", True
    if "searchparams" in lowered and tail in {"get", "getall"}:
        return "http_request", name, "network_to_application", True
    if lowered.startswith("process.env") or tail == "getenv":
        return "environment", name, "environment_to_application", None
    if tail in {"readfile", "readfilesync", "readtext"}:
        return "file", name, "filesystem_to_application", None
    if any(
        marker in lowered
        for marker in ("similaritysearch", "retriever.invoke", ".retrieve", "vectorstore")
    ):
        return "retrieved_document", name, "retrieval_to_prompt", None
    if tail in {"query", "execute", "findmany", "findone", "fetchall"} and any(
        marker in lowered for marker in ("db", "prisma", "sql", "knex", "pool", "client")
    ):
        return "database", name, "database_to_application", None
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _spread(node: ObjectExpr | None) -> Node | None:
    """The argument of the first ``...spread`` in an object literal."""
    if node is None:
        return None
    for prop in node.properties:
        if prop.key is None and prop.computed:
            return prop.value
    return None


def _prop(node: ObjectExpr | None, key: str) -> Node | None:
    if node is None:
        return None
    for prop in node.properties:
        if prop.key == key:
            return prop.value
    return None


def _resolve(module: JsModule, node: Node | None, depth: int = 0) -> Node | None:
    """Follow identifier bindings to the value they were assigned."""
    if node is None or depth > _MAX_DEPTH:
        return node
    if isinstance(node, AwaitExpr):
        return _resolve(module, node.argument, depth + 1)
    if isinstance(node, Identifier):
        assignment = module.assignment_for(node.name, node)
        if assignment is None:
            return node
        return _resolve(module, assignment.value, depth + 1)
    return node


def _resolve_anywhere(
    project: ProjectIndex | None, module: JsModule, node: Node | None, depth: int = 0
) -> tuple[JsModule, Node | None]:
    """Like :func:`_resolve`, but also through an import the index resolves."""
    if node is None or depth > _MAX_DEPTH:
        return module, node
    if isinstance(node, AwaitExpr):
        return _resolve_anywhere(project, module, node.argument, depth + 1)
    if isinstance(node, Identifier):
        assignment = module.assignment_for(node.name, node)
        if assignment is not None:
            return _resolve_anywhere(project, module, assignment.value, depth + 1)
        if project is not None:
            symbol = project.js_symbol(module, node.name)
            if symbol is not None and symbol.value is not None:
                return _resolve_anywhere(project, symbol.module, symbol.value, depth + 1)
    return module, node


def _static_value(module: JsModule, node: Node | None, depth: int = 0) -> object | None:
    """Return a statically known value, or None when it cannot be proven."""
    if node is None or depth > _MAX_DEPTH:
        return None
    if isinstance(node, Literal):
        return node.value
    if isinstance(node, Identifier):
        assignment = module.assignment_for(node.name, node)
        if assignment is None:
            return None
        return _static_value(module, assignment.value, depth + 1)
    if isinstance(node, TemplateLiteral):
        if node.expressions:
            return None
        return "".join(node.quasis)
    if isinstance(node, BinaryExpr) and node.op == "+":
        left = _static_value(module, node.left, depth + 1)
        right = _static_value(module, node.right, depth + 1)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        return None
    if isinstance(node, AwaitExpr):
        return _static_value(module, node.argument, depth + 1)
    return None


def _same_file_reachability(
    module: JsModule, call: CallExpr
) -> tuple[Reachability, list[str]]:
    """Walk enclosing scopes for a framework entrypoint."""
    scope = module.scope_for(call)
    path: list[str] = []
    while scope:
        info = module.functions.get(scope)
        if info is None:
            break
        path.insert(0, info.name)
        if info.entrypoint_kind is not None:
            return Reachability.TRUE, [f"{info.entrypoint_kind}:{info.name}", *path[1:]]
        scope = scope.rsplit(".", 1)[0] if "." in scope else ""
    return Reachability.UNKNOWN, []


def _reachability(
    module: JsModule, call: CallExpr, project: ProjectIndex | None = None
) -> tuple[Reachability, list[str]]:
    """Same-file reachability, extended through resolved cross-file callers.

    Without a resolved caller the same-file verdict stands: ``unknown`` is
    never upgraded to ``false``.
    """
    verdict, path = _same_file_reachability(module, call)
    if verdict is Reachability.TRUE or project is None:
        return verdict, path
    function = module.enclosing_function(call)
    while function is not None and "." in function.qualified_name:
        # Reachability is decided by the outermost named function.
        parent = module.functions.get(function.qualified_name.rsplit(".", 1)[0])
        if parent is None:
            break
        function = parent
    if function is None:
        return verdict, path
    queue: list[tuple[JsModule, JsFunctionInfo, list[str]]] = [
        (module, function, [f"{module.relative_path}:{function.name}"])
    ]
    seen: set[tuple[str, str]] = set()
    while queue:
        current_module, current, trail = queue.pop(0)
        key = (current_module.relative_path, current.qualified_name)
        if key in seen or len(trail) > MAX_CALL_DEPTH + 1:
            continue
        seen.add(key)
        for caller_module, caller_call in project.js_callers(current_module, current)[
            :MAX_CALL_SITES
        ]:
            caller_verdict, caller_path = _same_file_reachability(caller_module, caller_call)
            if caller_verdict is Reachability.TRUE:
                return Reachability.TRUE, [*caller_path, *trail]
            caller = caller_module.enclosing_function(caller_call)
            if caller is not None:
                hop = f"{caller_module.relative_path}:{caller.name}"
                queue.append((caller_module, caller, [hop, *trail]))
    return verdict, path
