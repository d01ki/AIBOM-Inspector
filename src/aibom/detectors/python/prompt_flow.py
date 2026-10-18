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
from aibom.detectors.project import (
    MAX_CALL_DEPTH,
    MAX_CALL_SITES,
    Budget,
    ProjectIndex,
    python_returns,
)
from aibom.detectors.python.common import argument_node, require_python
from aibom.detectors.python.parser import FunctionInfo, PythonModule
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
from aibom.models.evidence import Evidence

_MAX_DEPTH = 20
_MAX_HELPER_DEPTH = 3
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
            tools = _bound_tools(module, call, context.project)
            tool_refs = [tool.name for tool in tools]
            capabilities = _bound_tool_capabilities(tools, self.detector_id, context.project)
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
        trace = _FlowTracer(module, context.project).trace(expression)
        reachable, reachability_path = cross_file_reachability(module, call, context.project)

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


@dataclass(frozen=True)
class _Frame:
    """One resolved call the tracer descended into: params bind to ``call``'s args."""

    module_path: str
    function: str
    caller: _FlowTracer
    call: ast.Call


# Calls whose result is a plain transformation of their inputs.  Tainted input
# through one of these is still a *proven* flow; through any other call that
# the index cannot resolve, it is only a potential one.
_TRANSPARENT_CALLS = frozenset(
    {"str", "repr", "format", "textwrap.dedent", "json.dumps", "dict", "list", "tuple"}
)
_TRANSPARENT_METHODS = frozenset(
    {
        "format",
        "join",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
        "replace",
        "split",
        "splitlines",
        "encode",
        "decode",
        "removeprefix",
        "removesuffix",
        "get",
    }
)

_SeenKey = tuple[str, str | None, str]


class _FlowTracer:
    """Conservative expression tracer, bounded in depth, call depth, and visits.

    Within a file it follows assignments and expression composition.  With a
    :class:`ProjectIndex` it also follows, across files when needed:

    * a parameter of an ordinary function back to the arguments at its resolved
      call sites (``call_argument``);
    * a call into a project function through that function's ``return``
      expressions, with its parameters bound to this call's arguments
      (``call_return``) -- so a helper that ignores its input does not taint;
    * an imported name to the module-level binding that defines it
      (``import_reference``).

    Anything outside that subset stays ``unknown`` or, for an unresolved call
    that receives tainted input, is marked ``unresolved_call`` (potential).
    """

    def __init__(
        self,
        module: PythonModule,
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

    def trace(self, node: ast.AST) -> FlowTrace:
        return self._trace(node, set(), 0)

    def _spawn(
        self,
        module: PythonModule,
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

    def _trace(self, node: ast.AST, seen: set[_SeenKey], depth: int) -> FlowTrace:
        if depth > _MAX_DEPTH:
            return FlowTrace(None, steps=(self._step(node, None, "max_depth"),))
        if not self.budget.spend():
            return FlowTrace(None, steps=(self._step(node, None, "analysis_budget_exhausted"),))

        if isinstance(node, ast.Constant):
            return FlowTrace(False)

        if isinstance(node, ast.Name):
            source = self._parameter_source(node)
            if source is not None:
                return self._source(node, *source)
            named = _named_source(node.id)
            if named is not None:
                return self._source(node, *named)
            key = (self.module.relative_path, self.module.scope_for(node), node.id)
            if key in seen:
                return FlowTrace(None, steps=(self._step(node, node.id, "cycle"),))
            assignment = self.module.assignment_for(node.id, node)
            if assignment is None:
                crossed = self._parameter_flow(node, {*seen, key}, depth)
                if crossed is None:
                    crossed = self._import_flow(node, {*seen, key}, depth)
                if crossed is not None:
                    return crossed
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
            summarized = self._call_summary(node, seen, depth)
            if summarized is not None:
                return summarized
            children = [*node.args, *(kw.value for kw in node.keywords)]
            if isinstance(node.func, ast.Attribute):
                children.append(node.func.value)
            traced = combine_traces(
                *(self._trace(child, seen, depth + 1) for child in children)
            )
            if traced.user_controlled is True and not _transparent_call(node, qualified):
                return _with_step(traced, self._step(node, qualified or None, "unresolved_call"))
            return traced

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

        if isinstance(node, ast.Await):
            return self._trace(node.value, seen, depth + 1)

        return FlowTrace(None, steps=(self._step(node, None, "dynamic_expression"),))

    # -- interprocedural ----------------------------------------------------

    def _parameter_flow(
        self, node: ast.Name, seen: set[_SeenKey], depth: int
    ) -> FlowTrace | None:
        """Bind a parameter of an ordinary function to its call-site arguments."""
        function = self.module.enclosing_function(node)
        if function is None or node.id not in _function_parameters(function.node):
            return None
        for frame in reversed(self.frames):
            if (
                frame.module_path == self.module.relative_path
                and frame.function == function.qualified_name
            ):
                argument = _argument_for(frame.call, function.node, node.id)
                if argument is None:
                    return FlowTrace(None, steps=(self._step(node, node.id, "unbound_parameter"),))
                traced = frame.caller._trace(argument, seen, depth + 1)
                return _with_step(traced, frame.caller._step(argument, node.id, "call_argument"))
        if self.project is None or self.ascent >= MAX_CALL_DEPTH:
            return None
        callers = self.project.python_callers(self.module, function)
        if not callers:
            return None
        traces: list[FlowTrace] = []
        for caller_module, call in callers[:MAX_CALL_SITES]:
            argument = _argument_for(call, function.node, node.id)
            if argument is None:
                traces.append(FlowTrace(None))
                continue
            caller = self._spawn(caller_module, frames=(), ascent=self.ascent + 1)
            traced = caller._trace(argument, seen, depth + 1)
            traces.append(_with_step(traced, caller._step(argument, node.id, "call_argument")))
        if len(callers) > MAX_CALL_SITES:
            traces.append(
                FlowTrace(None, steps=(self._step(node, node.id, "analysis_budget_exhausted"),))
            )
        return combine_traces(*traces)

    def _call_summary(
        self, node: ast.Call, seen: set[_SeenKey], depth: int
    ) -> FlowTrace | None:
        """Trace a call into a project function through its return values."""
        if self.project is None or len(self.frames) >= MAX_CALL_DEPTH:
            return None
        target = self.project.python_function(self.module, node.func)
        if target is None:
            return None
        if any(
            frame.module_path == target.module.relative_path
            and frame.function == target.info.qualified_name
            for frame in self.frames
        ):
            return FlowTrace(None, steps=(self._step(node, target.info.name, "cycle"),))
        returns = python_returns(target.info.node)
        if returns is None:
            return None
        if not returns:
            return FlowTrace(False)
        frame = _Frame(target.module.relative_path, target.info.qualified_name, self, node)
        callee = self._spawn(target.module, frames=(*self.frames, frame))
        traced = combine_traces(
            *(
                _with_step(
                    callee._trace(item, seen, depth + 1),
                    callee._step(item, target.info.name, "return_value"),
                )
                for item in returns
            )
        )
        return _with_step(traced, self._step(node, target.info.name, "call_return"))

    def _import_flow(
        self, node: ast.Name, seen: set[_SeenKey], depth: int
    ) -> FlowTrace | None:
        """Follow an imported module-level binding into the module defining it."""
        if self.project is None or node.id not in self.module.aliases:
            return None
        symbol = self.project.python_symbol(self.module, node.id)
        if symbol is None:
            return None
        bindings = symbol.module.assignments.get((None, symbol.name))
        if not bindings:
            return None
        binding = max(bindings, key=lambda item: item.line)
        target = self._spawn(symbol.module)
        traced = target._trace(binding.value, seen, depth + 1)
        return _with_step(traced, target._step(binding.value, node.id, "import_reference"))

    # -- sources ------------------------------------------------------------

    def _parameter_source(
        self, node: ast.Name
    ) -> tuple[str, str, str, bool | None] | None:
        function = self.module.enclosing_function(node)
        if function is None or function.entrypoint_kind not in _UNTRUSTED_ENTRYPOINTS:
            return None
        if node.id not in _function_parameters(function.node):
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
        source = SourceRef(kind, _span(node), symbol, boundary, self.module.relative_path)
        return FlowTrace(
            user_controlled,
            (source,),
            (self._step(node, symbol, f"source:{kind}"),),
        )

    def _step(self, node: ast.AST, symbol: str | None, operation: str) -> ResolutionStep:
        return flow_step(self.module.relative_path, _span(node), symbol, operation)


def _with_step(trace: FlowTrace, step: ResolutionStep) -> FlowTrace:
    return FlowTrace(trace.user_controlled, trace.sources, (*trace.steps, step))


def _transparent_call(node: ast.Call, qualified: str) -> bool:
    if qualified in _TRANSPARENT_CALLS:
        return True
    return isinstance(node.func, ast.Attribute) and node.func.attr in _TRANSPARENT_METHODS


def _argument_for(
    call: ast.Call,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter: str,
) -> ast.AST | None:
    """The expression ``call`` binds to ``parameter``, including its default."""
    args = function.args
    for keyword in call.keywords:
        if keyword.arg == parameter:
            return keyword.value
    positional = [*args.posonlyargs, *args.args]
    names = [item.arg for item in positional]
    if parameter in names:
        index = names.index(parameter)
        if index < len(call.args) and not any(
            isinstance(item, ast.Starred) for item in call.args[: index + 1]
        ):
            return call.args[index]
        defaults = args.defaults
        offset = len(positional) - len(defaults)
        if index >= offset:
            return defaults[index - offset]
        return None
    for item, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if item.arg == parameter:
            return default
    return None


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


@dataclass(frozen=True)
class _BoundTool:
    """A tool listed in an agent's ``tools=[...]``, resolved to its definition."""

    name: str
    module: PythonModule
    function: ast.FunctionDef | ast.AsyncFunctionDef | None


def _bound_tools(
    module: PythonModule, call: ast.Call, project: ProjectIndex | None
) -> list[_BoundTool]:
    """Return explicit tools from an agent constructor's ``tools`` list.

    A tool may be defined in this file or imported from another module of the
    project; ``tools=TOOLS`` may name a list defined elsewhere.  A name that
    cannot be resolved keeps its place (so ``tool_refs`` stays complete) but
    carries no definition, and therefore never yields a capability.
    """
    expression = argument_node(call, ("tools",))
    if expression is None:
        return []
    located = _dereference_sequence_anywhere(module, expression, project)
    if located is None:
        return []
    owner, sequence = located
    found: list[_BoundTool] = []
    for item in sequence.elts:
        qualified = owner.qualified_name(item)
        if qualified is None:
            return []
        name = qualified.rsplit(".", 1)[-1]
        if any(existing.name == name for existing in found):
            continue
        found.append(_resolve_tool(owner, item, name, project))
    return found


def _resolve_tool(
    module: PythonModule, item: ast.AST, name: str, project: ProjectIndex | None
) -> _BoundTool:
    local = [info for info in module.functions.values() if info.name == name]
    if isinstance(item, ast.Name) and item.id not in module.aliases:
        node = local[0].node if len(local) == 1 else None
        return _BoundTool(name, module, node)
    if project is not None:
        target = project.python_function(module, item)
        if target is not None:
            return _BoundTool(name, target.module, target.info.node)
    return _BoundTool(name, module, None)


def _dereference_sequence_anywhere(
    module: PythonModule, expression: ast.AST, project: ProjectIndex | None
) -> tuple[PythonModule, ast.List | ast.Tuple] | None:
    sequence = _dereference_sequence(module, expression, set(), 0)
    if sequence is not None:
        return module, sequence
    if project is None or not isinstance(expression, ast.Name):
        return None
    symbol = project.python_symbol(module, expression.id)
    if symbol is None:
        return None
    bindings = symbol.module.assignments.get((None, symbol.name))
    if not bindings:
        return None
    value = max(bindings, key=lambda item: item.line).value
    if isinstance(value, (ast.List, ast.Tuple)):
        return symbol.module, value
    return None


def _bound_tool_capabilities(
    tools: list[_BoundTool],
    detector_id: str,
    project: ProjectIndex | None,
) -> list[ToolCapability]:
    """Classify high-impact calls only inside explicitly bound decorated tools.

    Operations are searched in the tool body and, through resolvable project
    calls, in helpers the tool passes its parameters to (bounded depth).  A
    capability is only reported when a tool parameter provably reaches the
    operation's arguments; a fixed command is not model-controlled.
    """
    found: list[ToolCapability] = []
    for tool in tools:
        if tool.function is None or not _is_recognized_tool(tool.module, tool.function):
            continue
        parameters = _function_parameters(tool.function)
        controlled = {parameter: {parameter} for parameter in parameters}
        found.extend(
            _capabilities_in(
                tool,
                tool.module,
                tool.function,
                controlled,
                detector_id,
                project,
                chain=[],
                visited=set(),
            )
        )
    return found


def _capabilities_in(
    tool: _BoundTool,
    module: PythonModule,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    controlled: dict[str, set[str]],
    detector_id: str,
    project: ProjectIndex | None,
    *,
    chain: list[Evidence],
    visited: set[tuple[str, int]],
) -> list[ToolCapability]:
    """Operations in ``function`` reached by the tool parameters in ``controlled``.

    ``controlled`` maps a local parameter to the *tool* parameters that flow
    into it, so a capability always names the model-controlled tool inputs.
    """
    key = (module.relative_path, function.lineno)
    if key in visited or len(chain) >= _MAX_HELPER_DEPTH:
        return []
    visited = {*visited, key}
    found: list[ToolCapability] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        qualified = module.qualified_name(node.func) or ""
        classified = _classify_capability(qualified, node)
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
            evidence = capability_evidence(
                module.relative_path,
                _span(node),
                detector_id,
                tool_name=tool.name,
                kind=kind,
                operation=qualified,
            )
            found.append(
                ToolCapability(
                    tool_name=tool.name,
                    kind=kind,
                    operation=qualified,
                    impact=impact,
                    severity=severity,
                    controlled_parameters=reached,
                    source_evidence=[*(item.model_copy() for item in chain), evidence],
                )
            )
            continue
        if project is None:
            continue
        helper = project.python_function(module, node.func)
        if helper is None:
            continue
        mapped: dict[str, set[str]] = {}
        for parameter in _function_parameters(helper.info.node):
            argument = _argument_for(node, helper.info.node, parameter)
            if argument is None:
                continue
            reached_by = {
                tool_parameter
                for local, tool_parameters in controlled.items()
                if _expression_uses_parameter(module, argument, local, set(), 0)
                for tool_parameter in tool_parameters
            }
            if reached_by:
                mapped[parameter] = reached_by
        if not mapped:
            continue
        hop = capability_evidence(
            module.relative_path,
            _span(node),
            detector_id,
            tool_name=tool.name,
            kind="helper_call",
            operation=helper.info.name,
        )
        hop.matched_pattern = f"bound-tool-helper:{helper.info.name}"
        found.extend(
            _capabilities_in(
                tool,
                helper.module,
                helper.info.node,
                mapped,
                detector_id,
                project,
                chain=[*chain, hop],
                visited=visited,
            )
        )
    return found


def cross_file_reachability(
    module: PythonModule, node: ast.AST, project: ProjectIndex | None
) -> tuple[Reachability, list[str]]:
    """Same-file reachability, extended through resolved cross-file callers.

    A sink in ``agents/main.py`` with no entrypoint of its own is reachable
    when a route in another module calls the function containing it.  The
    returned path names each hop as ``file:function``.  Without a resolved
    caller the same-file verdict stands, so ``unknown`` is never upgraded to
    ``false``.
    """
    verdict, path = module.reachability(node)
    if verdict is Reachability.TRUE or project is None:
        return verdict, path
    function = module.enclosing_function(node)
    if function is None:
        return verdict, path
    queue: list[tuple[PythonModule, FunctionInfo, list[str]]] = [
        (module, function, [f"{module.relative_path}:{function.name}"])
    ]
    seen: set[tuple[str, str]] = set()
    while queue:
        current_module, current, trail = queue.pop(0)
        key = (current_module.relative_path, current.qualified_name)
        if key in seen or len(trail) > MAX_CALL_DEPTH + 1:
            continue
        seen.add(key)
        for caller_module, call in project.python_callers(current_module, current)[
            :MAX_CALL_SITES
        ]:
            caller_verdict, caller_path = caller_module.reachability(call)
            if caller_verdict is Reachability.TRUE:
                return Reachability.TRUE, [*caller_path, *trail]
            caller = caller_module.enclosing_function(call)
            if caller is not None:
                hop = f"{caller_module.relative_path}:{caller.name}"
                queue.append((caller_module, caller, [hop, *trail]))
    return verdict, path


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
