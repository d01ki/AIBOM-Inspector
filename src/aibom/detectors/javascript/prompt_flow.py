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
    SpreadExpr,
    TemplateLiteral,
    UnaryExpr,
    children,
    walk,
)
from aibom.detectors.javascript.parser import JsFunctionInfo, JsModule
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
_SUPPORTED_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

# Vercel AI SDK core entrypoints; all take a single options object.
_AI_SDK_CALLS = frozenset(
    {"generateText", "streamText", "generateObject", "streamObject"}
)
_OPENAI_SUFFIXES = (
    ".responses.create",
    ".chat.completions.create",
    ".completions.create",
    ".beta.assistants.create",
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
            provider = _provider_for_call(module, call)
            if provider is None:
                continue
            options = _options_object(module, call)
            model_refs = _model_refs(module, options)
            tools = _bound_tools(module, options)
            capabilities = _tool_capabilities(context, module, tools, self.detector_id)
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
        trace = _FlowTracer(module).trace(expression)
        static_value = _static_value(module, expression)
        reachable, reachability_path = _reachability(module, call)

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


def _provider_for_call(module: JsModule, call: CallExpr) -> str | None:
    qualified = module.qualified_name(call.callee) or ""
    local = module.local_name(call.callee) or ""

    if (
        call.is_new
        and module.has_import("@openai/agents")
        and local.rsplit(".", 1)[-1] == "Agent"
    ):
        return "openai-agents"
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
        add(_prop(options, "system"), "system", f"ai.{family}.system")
        add(_prop(options, "prompt"), "user", f"ai.{family}.prompt")
        found.extend(
            _split_messages(module, _prop(options, "messages"), f"ai.{family}.messages")
        )
        return found

    if provider == "openai":
        qualified = module.qualified_name(call.callee) or ""
        if qualified.endswith(".beta.assistants.create"):
            add(
                _prop(options, "instructions"),
                "system",
                "openai.beta.assistants.create.instructions",
            )
            return found
        if qualified.endswith(".responses.create"):
            add(
                _prop(options, "instructions"),
                "system",
                "openai.responses.create.instructions",
            )
            add(_prop(options, "input"), "user", "openai.responses.create.input")
            return found
        found.extend(
            _split_messages(module, _prop(options, "messages"), "openai.messages")
        )
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


def _bound_tools(module: JsModule, options: ObjectExpr | None) -> list[BoundTool]:
    """Return tools explicitly bound by this call, with their executors.

    Only direct bindings count: an object map (Vercel AI SDK) or an array of
    tool bindings (OpenAI Agents).  A helper that merely sits in the same file
    is never promoted to a bound tool.
    """
    if options is None:
        return []
    node = _resolve(module, _prop(options, "tools"))
    found: list[BoundTool] = []
    if isinstance(node, ObjectExpr):
        for prop in node.properties:
            if prop.key is None:
                continue
            execute = _tool_executor(module, prop.value)
            if execute is not None:
                found.append(BoundTool(name=prop.key, execute=execute))
    elif isinstance(node, ArrayExpr):
        for element in node.elements:
            execute = _tool_executor(module, element)
            if execute is None:
                continue
            name = _tool_name(module, element) or (
                element.name if isinstance(element, Identifier) else "tool"
            )
            found.append(BoundTool(name=name, execute=execute))
    return found


def _tool_executor(module: JsModule, node: Node) -> FunctionNode | None:
    """Find the function a tool binding will run when the model calls it."""
    resolved = _resolve(module, node)
    if isinstance(resolved, CallExpr):
        for argument in resolved.args:
            options = _resolve(module, argument)
            if not isinstance(options, ObjectExpr):
                continue
            for key in ("execute", "handler", "func", "run"):
                candidate = _resolve(module, _prop(options, key))
                if isinstance(candidate, FunctionNode):
                    return candidate
    return None


def _tool_name(module: JsModule, node: Node) -> str | None:
    resolved = _resolve(module, node)
    if not isinstance(resolved, CallExpr):
        return None
    for argument in resolved.args:
        options = _resolve(module, argument)
        if isinstance(options, ObjectExpr):
            value = _static_value(module, _prop(options, "name"))
            if isinstance(value, str) and value:
                return value
    return None


def _tool_capabilities(
    context: ScanContext,
    module: JsModule,
    tools: list[BoundTool],
    detector_id: str,
) -> list[ToolCapability]:
    """Classify high-impact operations reachable from a bound tool's parameters."""
    found: list[ToolCapability] = []
    for tool in tools:
        parameters = _executor_parameters(tool.execute)
        if not parameters:
            continue
        for node in walk(tool.execute):
            if not isinstance(node, CallExpr):
                continue
            qualified = module.qualified_name(node.callee) or ""
            classified = _classify_capability(module, node, qualified)
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
            found.append(
                ToolCapability(
                    tool_name=tool.name,
                    kind=kind,
                    operation=qualified or "eval",
                    impact=impact,
                    severity=severity,
                    controlled_parameters=controlled,
                    source_evidence=[
                        capability_evidence(
                            context.relative_path,
                            _span(node),
                            detector_id,
                            tool_name=tool.name,
                            kind=kind,
                            operation=qualified,
                        )
                    ],
                )
            )
    return found


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


class _FlowTracer:
    """Conservative same-file expression tracer with a strict depth bound."""

    def __init__(self, module: JsModule) -> None:
        self.module = module

    def trace(self, node: Node) -> FlowTrace:
        return self._trace(node, set(), 0)

    def _trace(
        self, node: Node, seen: set[tuple[str | None, str]], depth: int
    ) -> FlowTrace:
        if depth > _MAX_DEPTH:
            return FlowTrace(None, steps=(self._step(node, None, "max_depth"),))

        if isinstance(node, Literal):
            return FlowTrace(False)

        if isinstance(node, Identifier):
            source = self._parameter_source(node)
            if source is not None:
                return self._source(node, *source)
            named = _named_source(node.name)
            if named is not None:
                return self._source(node, *named)
            key = (self.module.scope_for(node), node.name)
            if key in seen:
                return FlowTrace(None, steps=(self._step(node, node.name, "cycle"),))
            assignment = self.module.assignment_for(node.name, node)
            if assignment is None:
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
            traces = [self._trace(argument, seen, depth + 1) for argument in node.args]
            if isinstance(node.callee, MemberExpr):
                traces.append(self._trace(node.callee, seen, depth + 1))
            return combine_traces(*traces)

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
        source = SourceRef(kind, _span(node), symbol, boundary)
        return FlowTrace(
            user_controlled,
            (source,),
            (self._step(node, symbol, f"source:{kind}"),),
        )

    def _step(self, node: Node, symbol: str | None, operation: str) -> ResolutionStep:
        return flow_step(self.module.relative_path, _span(node), symbol, operation)


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


def _reachability(module: JsModule, call: CallExpr) -> tuple[Reachability, list[str]]:
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

