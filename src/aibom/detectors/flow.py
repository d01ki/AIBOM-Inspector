"""Language-agnostic pieces of the prompt source-to-sink analysis.

The Python and JavaScript/TypeScript detectors reason identically once a node
has been reduced to a :class:`Span`.  Everything that does not depend on a
specific syntax tree lives here so the two detectors cannot drift apart: the
trace algebra, the sanitized evidence builders, and the content hash.

Nothing here ever receives prompt text — only positions, symbols, and kinds.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from aibom.models.analysis import ResolutionStep
from aibom.models.evidence import Evidence


@dataclass(frozen=True)
class Span:
    """A 1-based source position, normalized across language front ends."""

    line: int
    end_line: int
    column: int


@dataclass(frozen=True)
class SourceRef:
    """An untrusted origin proven to reach a prompt sink."""

    kind: str
    span: Span
    symbol: str
    trust_boundary: str


@dataclass(frozen=True)
class FlowTrace:
    """The result of tracing one expression back toward its origins.

    ``user_controlled`` is deliberately three-valued: ``None`` means the tracer
    could not prove either way, and is never treated as safe.
    """

    user_controlled: bool | None
    sources: tuple[SourceRef, ...] = ()
    steps: tuple[ResolutionStep, ...] = ()


def combine_traces(*traces: FlowTrace) -> FlowTrace:
    """Merge sibling traces, keeping the most conservative verdict."""
    if not traces:
        return FlowTrace(None)
    state: bool | None
    if any(trace.user_controlled is True for trace in traces):
        state = True
    elif any(trace.user_controlled is None for trace in traces):
        state = None
    else:
        state = False

    sources: list[SourceRef] = []
    steps: list[ResolutionStep] = []
    source_keys: set[tuple[str, int, str]] = set()
    step_keys: set[tuple[str, int | None, int | None, str | None, str]] = set()
    for trace in traces:
        for source in trace.sources:
            source_key = (source.kind, source.span.line, source.symbol)
            if source_key not in source_keys:
                sources.append(source)
                source_keys.add(source_key)
        for step in trace.steps:
            step_key = (step.file, step.line, step.column, step.symbol, step.operation)
            if step_key not in step_keys:
                steps.append(step)
                step_keys.add(step_key)
    steps.sort(key=lambda item: 0 if item.operation.startswith("source:") else 1)
    return FlowTrace(state, tuple(sources), tuple(steps))


def flow_step(file: str, span: Span, symbol: str | None, operation: str) -> ResolutionStep:
    """Record one hop of the trace without retaining the value."""
    return ResolutionStep(
        file=file,
        line=span.line,
        column=span.column or None,
        symbol=symbol,
        value=None,
        operation=operation,
    )


def sink_evidence(file: str, span: Span, detector_id: str, sink_kind: str) -> Evidence:
    return _evidence(
        file,
        span,
        detector_id,
        kind="sink",
        snippet=f"<prompt sink:{sink_kind}>",
        pattern="prompt-sink",
        confidence=0.98,
    )


def source_evidence(file: str, source: SourceRef, detector_id: str) -> Evidence:
    return _evidence(
        file,
        source.span,
        detector_id,
        kind="source",
        snippet=f"<prompt source:{source.kind}>",
        pattern=f"prompt-source:{source.kind}",
        confidence=0.9,
    )


def capability_evidence(
    file: str,
    span: Span,
    detector_id: str,
    *,
    tool_name: str,
    kind: str,
    operation: str,
) -> Evidence:
    return _evidence(
        file,
        span,
        detector_id,
        kind="capability",
        snippet=f"<bound tool capability:{tool_name}:{kind}>",
        pattern=f"bound-tool-capability:{operation}",
        confidence=0.98,
    )


def _evidence(
    file: str,
    span: Span,
    detector_id: str,
    *,
    kind: str,
    snippet: str,
    pattern: str,
    confidence: float,
) -> Evidence:
    return Evidence(
        file=file,
        line_start=span.line,
        line_end=span.end_line,
        column_start=span.column,
        snippet=snippet,
        matched_pattern=pattern,
        confidence=confidence,
        detector_id=detector_id,
        kind=kind,
    )


def content_hash(value: object | None) -> str:
    """Hash a statically known prompt so the body is never serialized."""
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
