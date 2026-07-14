"""Shared helpers for provider-specific Python AST detectors."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from aibom.detectors.base import ScanContext
from aibom.detectors.python.parser import PythonModule
from aibom.detectors.python.value_resolver import ResolvedValue, ValueResolver
from aibom.models.analysis import (
    ConfidenceFactors,
    Reachability,
    UsageState,
    ValueResolution,
)
from aibom.models.entities import Dataset, Model, Service
from aibom.models.evidence import Evidence

_SENSITIVE_VALUE = re.compile(
    r"(?i)(?:^sk-(?:ant-)?[A-Za-z0-9_-]{12,}$|password|api[_-]?key|secret|bearer\s+)"
)
_PROVIDER_KEY = re.compile(r"\b(?:sk-ant-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9]{16,})\b")
_SECRET_ARGUMENT = re.compile(
    r"(?i)((?:api[_-]?key|secret|token|password|access[_-]?key)\s*=\s*['\"])[^'\"]+"
)
_URL = re.compile(r"https?://[^'\"\s)]+")


@dataclass(frozen=True)
class ResolvedArgument:
    value: ResolvedValue
    expression: ast.AST


def evidence(
    context: ScanContext,
    node: ast.AST,
    detector_id: str,
    pattern: str,
    confidence: float,
) -> Evidence:
    module = require_python(context)
    line_start = getattr(node, "lineno", 1)
    line_end = getattr(node, "end_lineno", line_start)
    column_start = getattr(node, "col_offset", 0) + 1
    raw_end = getattr(node, "end_col_offset", None)
    return Evidence(
        file=context.relative_path,
        line_start=line_start,
        line_end=line_end,
        column_start=column_start,
        column_end=raw_end,
        snippet=_redact_evidence_snippet(module.source_segment(node)),
        matched_pattern=pattern,
        confidence=confidence,
        detector_id=detector_id,
        kind="ast",
    )


def service_entity(
    context: ScanContext,
    node: ast.AST,
    *,
    detector_id: str,
    name: str,
    endpoint: str,
    state: str,
    pattern: str,
    confidence: float,
) -> Service:
    module = require_python(context)
    reachable, path = (
        module.reachability(node) if state == "invoked" else (Reachability.UNKNOWN, [])
    )
    usage = UsageState(
        declared=True,
        imported=state in {"imported", "instantiated", "invoked"},
        instantiated=state in {"instantiated", "invoked"},
        invoked=state == "invoked",
        reachable=reachable,
    )
    return Service(
        name=name,
        kind="api",
        endpoint=endpoint,
        source_evidence=[evidence(context, node, detector_id, pattern, confidence)],
        detector_ids=[detector_id],
        usage=usage,
        confidence_factors=ConfidenceFactors(
            syntax_confidence=1.0,
            framework_identification_confidence=1.0,
            reachability_confidence=_reachability_confidence(reachable),
        ),
        reachability_path=path,
        source_contexts=[context.source_context],
    )


def model_entity(
    context: ScanContext,
    call: ast.Call,
    argument: ResolvedArgument,
    *,
    detector_id: str,
    provider: str,
    pattern: str,
    revision: str | None = None,
) -> Model:
    module = require_python(context)
    resolved = argument.value
    reachable, path = module.reachability(call)
    sensitive = isinstance(resolved.value, str) and _looks_sensitive(resolved.value)
    if (
        resolved.resolved
        and isinstance(resolved.value, str)
        and resolved.value.strip()
        and not sensitive
    ):
        name = resolved.value.strip()
        status = ValueResolution.RESOLVED
        confidence = min(0.98, 0.78 + (0.2 * resolved.confidence))
        resolution_path = list(resolved.steps)
    else:
        marker = resolved.environment_variable or f"{context.relative_path}:{call.lineno}"
        prefix = "redacted" if sensitive else "unresolved"
        name = f"{prefix}:{marker}"
        status = ValueResolution.UNRESOLVED
        confidence = 0.55
        resolution_path = [
            step.model_copy(update={"value": "<redacted>" if step.value else None})
            for step in resolved.steps
        ]
    return Model(
        name=name,
        provider=provider,
        revision=revision,
        revision_pinned=revision is not None,
        environment_variable=resolved.environment_variable,
        source_evidence=[evidence(context, call, detector_id, pattern, confidence)],
        detector_ids=[detector_id],
        usage=UsageState(
            declared=True,
            imported=True,
            instantiated=True,
            invoked=True,
            reachable=reachable,
        ),
        confidence_factors=ConfidenceFactors(
            syntax_confidence=1.0,
            value_resolution_confidence=resolved.confidence,
            framework_identification_confidence=1.0,
            reachability_confidence=_reachability_confidence(reachable),
        ),
        resolution_path=resolution_path,
        reachability_path=path,
        source_contexts=[context.source_context],
        value_resolution=status,
    )


def dataset_entity(
    context: ScanContext,
    call: ast.Call,
    argument: ResolvedArgument,
    *,
    detector_id: str,
    pattern: str,
) -> Dataset | None:
    resolved = argument.value
    if not resolved.resolved or not isinstance(resolved.value, str) or not resolved.value.strip():
        return None
    module = require_python(context)
    reachable, path = module.reachability(call)
    confidence = min(0.98, 0.78 + (0.2 * resolved.confidence))
    return Dataset(
        name=resolved.value.strip(),
        source="huggingface",
        source_evidence=[evidence(context, call, detector_id, pattern, confidence)],
        detector_ids=[detector_id],
        usage=UsageState(
            declared=True,
            imported=True,
            instantiated=True,
            invoked=True,
            reachable=reachable,
        ),
        confidence_factors=ConfidenceFactors(
            syntax_confidence=1.0,
            value_resolution_confidence=resolved.confidence,
            framework_identification_confidence=1.0,
            reachability_confidence=_reachability_confidence(reachable),
        ),
        resolution_path=list(resolved.steps),
        reachability_path=path,
        source_contexts=[context.source_context],
        value_resolution=ValueResolution.RESOLVED,
    )


def argument_node(
    call: ast.Call,
    names: tuple[str, ...],
    *,
    positional: int | None = None,
) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg in names:
            return keyword.value
    if positional is not None and len(call.args) > positional:
        return call.args[positional]
    return None


def resolve_argument(
    module: PythonModule,
    call: ast.Call,
    expression: ast.AST,
    resolver: ValueResolver,
) -> list[ResolvedArgument]:
    """Resolve directly, then trace a simple wrapper-function parameter."""
    direct = resolver.resolve(expression)
    if direct.resolved or direct.environment_variable is not None:
        return [ResolvedArgument(direct, expression)]
    if not isinstance(expression, ast.Name):
        return [ResolvedArgument(direct, expression)]

    function = module.enclosing_function(call)
    if function is None:
        return [ResolvedArgument(direct, expression)]
    params = [*function.node.args.posonlyargs, *function.node.args.args]
    try:
        position = next(i for i, param in enumerate(params) if param.arg == expression.id)
    except StopIteration:
        return [ResolvedArgument(direct, expression)]

    found: list[ResolvedArgument] = []
    for wrapper_call in module.calls:
        if wrapper_call is call:
            continue
        called = module.qualified_name(wrapper_call.func)
        if called is None or called.split(".")[-1] != function.name:
            continue
        supplied = argument_node(wrapper_call, (expression.id,), positional=position)
        if supplied is None:
            continue
        resolved = resolver.resolve(supplied)
        if resolved.resolved or resolved.environment_variable is not None:
            found.append(ResolvedArgument(resolved, supplied))
    return found or [ResolvedArgument(direct, expression)]


def imported_roots(node: ast.Import | ast.ImportFrom) -> set[str]:
    if isinstance(node, ast.Import):
        return {alias.name.split(".", 1)[0] for alias in node.names}
    return {(node.module or "").split(".", 1)[0]}


def assigned_name(module: PythonModule, call: ast.Call) -> str | None:
    parent = module.parents.get(id(call))
    if isinstance(parent, (ast.Assign, ast.AnnAssign)):
        target = parent.targets[0] if isinstance(parent, ast.Assign) else parent.target
        if isinstance(target, ast.Name):
            return target.id
    return None


def root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def revision_value(call: ast.Call, resolver: ValueResolver) -> str | None:
    expression = argument_node(call, ("revision",))
    if expression is None:
        return None
    resolved = resolver.resolve(expression)
    return str(resolved.value) if resolved.resolved and resolved.value is not None else None


def safe_endpoint(value: object | None) -> str | None:
    """Return an HTTP(S) endpoint without credentials, query, or fragment."""
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def require_python(context: ScanContext) -> PythonModule:
    if context.python is None:
        raise ValueError("Python detector received an unparsed context")
    return context.python


def _reachability_confidence(value: Reachability) -> float:
    return 0.85 if value is not Reachability.UNKNOWN else 0.25


def _looks_sensitive(value: str) -> bool:
    stripped = value.strip()
    if _SENSITIVE_VALUE.search(stripped):
        return True
    # Long, whitespace-free opaque values are more likely credentials than
    # provider model IDs. Slashes/dots/hyphens keep normal model names visible.
    return len(stripped) >= 48 and stripped.isalnum()


def _redact_evidence_snippet(value: str) -> str:
    redacted = _PROVIDER_KEY.sub("<redacted>", value)
    redacted = _SECRET_ARGUMENT.sub(r"\1<redacted>", redacted)

    def sanitize_url(match: re.Match[str]) -> str:
        return safe_endpoint(match.group(0)) or "<redacted-url>"

    return _URL.sub(sanitize_url, redacted)
