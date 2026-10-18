"""Evidence-backed blast-radius paths for tool-using AI agents.

An impact path is deliberately stricter than co-location.  It exists only when
the prompt lineage proves untrusted input reaches privileged instructions and
the same agent constructor directly binds a decorated tool whose body contains
a recognized security-relevant operation.

Two properties are kept separate on every path:

* ``severity`` — the *potential* impact class of the operation the tool can
  reach (``critical`` for command execution).  It is never a statement that an
  attack succeeds.
* ``evidence_level`` — how much of the path is proven.  ``proven_static``
  means every hop was resolved statically; ``potential`` means the input is
  user-controlled but some hop relied on an assumption (taint through a call
  the index cannot see, or an unresolved route to an entrypoint).  A potential
  path is reported, but it is never allowed to carry a ``critical`` verdict.

Privileged prompts with a bound capability whose input could not be resolved
either way are returned separately by :func:`build_unresolved_impacts`: they
are worth showing, and they must not be mistaken for either safe or exploitable.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from aibom.detectors.flow import CROSS_BOUNDARY_OPERATIONS, POTENTIAL_OPERATIONS
from aibom.exposure import build_exposure_paths, prompt_slots
from aibom.inventory import Inventory
from aibom.models.analysis import Reachability, ResolutionStep
from aibom.models.entities import Prompt, ToolCapability
from aibom.models.evidence import Evidence
from aibom.models.findings import Severity

PROVEN_STATIC = "proven_static"
POTENTIAL = "potential"
UNKNOWN = "unknown"

_PRIVILEGED = {"system", "developer"}
_STATIC_LIMITATION = (
    "Static path only: the model choosing the tool, the attacker producing the "
    "required arguments, and runtime exploitation are not proven."
)
_MIDDLEWARE_LIMITATION = (
    "Authorization middleware, runtime approvals and provider guardrails are not modeled."
)
_FLOW_HOP_OPERATIONS = CROSS_BOUNDARY_OPERATIONS | {"return_value", "unresolved_call"}


class PathNode(BaseModel):
    """One node of an impact path, for graph rendering and audit."""

    role: str = Field(description="source | flow | privileged_prompt | model | tool | operation")
    label: str
    file: str | None = None
    line: int | None = None
    status: str = Field(default=PROVEN_STATIC, description="proven_static | potential | unknown")
    detail: str | None = None


class ImpactPath(BaseModel):
    """A potential attacker-steering path from input to an agent capability."""

    id: str
    exposure_path_id: str
    prompt_anchor: str
    prompt_id: str
    prompt_name: str
    source_kind: str
    sink_kind: str
    trust_boundary: str
    model_names: list[str] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)
    capabilities: list[ToolCapability] = Field(default_factory=list)
    severity: Severity
    reachable: Reachability
    confidence: float = Field(ge=0.0, le=1.0)
    binding: str = "direct_agent_tool_binding"
    source_evidence: list[Evidence] = Field(default_factory=list)
    evidence_level: str = Field(
        default=PROVEN_STATIC,
        description="proven_static | potential | unknown; independent of severity.",
    )
    impact_severity: Severity | None = Field(
        default=None,
        description="Uncapped impact class of the reachable operation.",
    )
    cross_file: bool = False
    semantic_key: str = Field(
        default="",
        description="Line- and file-insensitive identity used to match paths across revisions.",
    )
    limitations: list[str] = Field(default_factory=list)
    nodes: list[PathNode] = Field(default_factory=list)

    @property
    def consequence(self) -> str:
        return "; ".join(dict.fromkeys(item.impact for item in self.capabilities))


def build_impact_paths(inventory: Inventory) -> list[ImpactPath]:
    """Return only strongly linked prompt-to-capability paths."""
    prompts = {
        entity.id: entity
        for entity in inventory.entities
        if isinstance(entity, Prompt)
    }
    paths: list[ImpactPath] = []
    for exposure in build_exposure_paths(inventory):
        prompt = prompts.get(exposure.prompt_id)
        if (
            prompt is None
            or not exposure.privileged
            or exposure.reachable is Reachability.FALSE
            or not prompt.capabilities
        ):
            continue
        capabilities = _sorted_capabilities(prompt)
        impact_severity = _max_severity(capabilities)
        tool_names = sorted({item.tool_name for item in capabilities})
        identity = "\x1f".join((exposure.id, _signature(capabilities)))
        evidence = [item.model_copy() for item in exposure.source_evidence]
        for capability in capabilities:
            evidence.extend(item.model_copy() for item in capability.source_evidence)
        confidence = min((item.confidence for item in evidence), default=0.0)
        level, limitations = _evidence_level(prompt.data_flow_path, exposure.reachable)
        severity = impact_severity
        if level != PROVEN_STATIC and severity.rank > Severity.HIGH.rank:
            # A potential path is shown, but never as a Critical verdict.
            severity = Severity.HIGH
        paths.append(
            ImpactPath(
                id=f"impact:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}",
                exposure_path_id=exposure.id,
                prompt_anchor=exposure.prompt_anchor,
                prompt_id=prompt.id,
                prompt_name=prompt.name,
                source_kind=exposure.source_kind,
                sink_kind=exposure.sink_kind,
                trust_boundary=exposure.trust_boundary,
                model_names=list(exposure.model_names),
                tool_names=tool_names,
                capabilities=capabilities,
                severity=severity,
                reachable=exposure.reachable,
                confidence=confidence,
                source_evidence=_dedupe_evidence(evidence),
                evidence_level=level,
                impact_severity=impact_severity,
                cross_file=_cross_file(prompt, capabilities),
                semantic_key=semantic_key(
                    exposure.source_kind, exposure.sink_kind, exposure.trust_boundary, capabilities
                ),
                limitations=limitations,
                nodes=_nodes(prompt, list(exposure.model_names), capabilities, level),
            )
        )
    return sorted(paths, key=lambda path: (-path.severity.rank, path.id))


def build_unresolved_impacts(inventory: Inventory) -> list[ImpactPath]:
    """Privileged prompts with a steerable bound tool and an *unresolved* input.

    These are not findings: the input may well be constant.  They exist so a
    reviewer — and a drift report — can see that the analysis stopped short,
    instead of reading the silence as safety.
    """
    found: list[ImpactPath] = []
    for slot in prompt_slots(inventory):
        prompt = slot.prompt
        if (
            prompt.kind not in _PRIVILEGED
            or prompt.user_controlled is not None
            or not prompt.capabilities
            or prompt.usage.reachable is Reachability.FALSE
        ):
            continue
        capabilities = _sorted_capabilities(prompt)
        stops = sorted(
            {
                f"{step.operation} at {step.file}:{step.line}"
                for step in prompt.data_flow_path
                if step.operation
                in {"unknown_symbol", "dynamic_expression", "max_depth", "cycle"}
                | POTENTIAL_OPERATIONS
            }
        )
        identity = "\x1f".join(("unresolved", slot.anchor, _signature(capabilities)))
        sink = [item.model_copy() for item in prompt.source_evidence if item.kind == "sink"]
        found.append(
            ImpactPath(
                id=f"impact-unknown:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}",
                exposure_path_id="",
                prompt_anchor=slot.anchor,
                prompt_id=prompt.id,
                prompt_name=prompt.name,
                source_kind="unresolved",
                sink_kind=prompt.sink_kind or "",
                trust_boundary="unknown",
                model_names=list(prompt.model_refs),
                tool_names=sorted({item.tool_name for item in capabilities}),
                capabilities=capabilities,
                severity=Severity.INFO,
                reachable=prompt.usage.reachable,
                confidence=0.0,
                source_evidence=sink,
                evidence_level=UNKNOWN,
                impact_severity=_max_severity(capabilities),
                cross_file=_cross_file(prompt, capabilities),
                semantic_key=semantic_key(
                    "unresolved", prompt.sink_kind or "", "unknown", capabilities
                ),
                limitations=[
                    "The origin of the privileged instruction could not be resolved "
                    "statically; this is neither proven safe nor proven reachable.",
                    *(f"Analysis stopped: {stop}." for stop in stops[:5]),
                ],
                nodes=_nodes(prompt, list(prompt.model_refs), capabilities, UNKNOWN),
            )
        )
    return sorted(found, key=lambda path: path.id)


def semantic_key(
    source_kind: str, sink_kind: str, trust_boundary: str, capabilities: list[ToolCapability]
) -> str:
    """Identity that survives line shifts, file moves and local renames."""
    raw = "\x1f".join((source_kind, sink_kind, trust_boundary, _signature(capabilities)))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _sorted_capabilities(prompt: Prompt) -> list[ToolCapability]:
    return sorted(
        (item.model_copy(deep=True) for item in prompt.capabilities),
        key=lambda item: (item.tool_name, item.kind, item.operation),
    )


def _max_severity(capabilities: list[ToolCapability]) -> Severity:
    return max((Severity(item.severity) for item in capabilities), key=lambda item: item.rank)


def _signature(capabilities: list[ToolCapability]) -> str:
    return "\x1f".join(
        (
            f"{item.tool_name}:{item.kind}:{item.operation}:"
            f"{','.join(item.controlled_parameters)}"
        )
        for item in capabilities
    )


def _evidence_level(
    steps: list[ResolutionStep], reachable: Reachability
) -> tuple[str, list[str]]:
    limitations: list[str] = []
    for step in steps:
        if step.operation == "unresolved_call":
            limitations.append(
                f"Untrusted input passes through a call that was not resolved "
                f"({step.symbol or 'call'} at {step.file}:{step.line}); propagation is assumed."
            )
        elif step.operation == "analysis_budget_exhausted":
            limitations.append(
                f"An analysis bound was reached at {step.file}:{step.line}; "
                "the path was not fully explored."
            )
    if reachable is not Reachability.TRUE:
        limitations.append("No resolved route from an application entrypoint to the sink.")
    level = POTENTIAL if limitations else PROVEN_STATIC
    return level, [*dict.fromkeys(limitations), _MIDDLEWARE_LIMITATION, _STATIC_LIMITATION]


def _cross_file(prompt: Prompt, capabilities: list[ToolCapability]) -> bool:
    files = {step.file for step in prompt.data_flow_path}
    files.update(item.file for item in prompt.source_evidence)
    for capability in capabilities:
        files.update(item.file for item in capability.source_evidence)
    return len(files) > 1


def _nodes(
    prompt: Prompt,
    models: list[str],
    capabilities: list[ToolCapability],
    level: str,
) -> list[PathNode]:
    """Ordered source -> flow -> prompt -> model -> tool -> operation nodes."""
    nodes: list[PathNode] = []
    sink = next((item for item in prompt.source_evidence if item.kind == "sink"), None)
    for item in prompt.source_evidence:
        if item.kind == "source":
            nodes.append(
                PathNode(
                    role="source",
                    label=prompt.source_kind or "untrusted input",
                    file=item.file,
                    line=item.line_start,
                    detail=prompt.trust_boundary,
                )
            )
    if not any(node.role == "source" for node in nodes):
        nodes.append(PathNode(role="source", label="unresolved input", status=UNKNOWN))
    seen: set[tuple[str, int | None, str]] = set()
    for step in prompt.data_flow_path:
        if step.operation not in _FLOW_HOP_OPERATIONS:
            continue
        key = (step.file, step.line, step.operation)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(
            PathNode(
                role="flow",
                label=step.operation.replace("_", " "),
                file=step.file,
                line=step.line,
                status=POTENTIAL if step.operation in POTENTIAL_OPERATIONS else PROVEN_STATIC,
                detail=step.symbol,
            )
        )
    nodes.append(
        PathNode(
            role="privileged_prompt",
            label=prompt.sink_kind or prompt.kind,
            file=sink.file if sink else None,
            line=sink.line_start if sink else None,
            detail=f"{prompt.kind} instructions",
        )
    )
    nodes.append(
        PathNode(
            role="model",
            label=", ".join(models) if models else "unresolved model",
            file=sink.file if sink else None,
            line=sink.line_start if sink else None,
            status=PROVEN_STATIC if models else UNKNOWN,
        )
    )
    for capability in capabilities:
        first = capability.source_evidence[0] if capability.source_evidence else None
        last = capability.source_evidence[-1] if capability.source_evidence else None
        nodes.append(
            PathNode(
                role="tool",
                label=capability.tool_name,
                file=first.file if first else None,
                line=first.line_start if first else None,
                detail="explicitly bound; parameters "
                + ", ".join(capability.controlled_parameters),
            )
        )
        nodes.append(
            PathNode(
                role="operation",
                label=capability.operation,
                file=last.file if last else None,
                line=last.line_start if last else None,
                detail=f"{capability.kind}: {capability.impact}",
            )
        )
    return nodes


def _dedupe_evidence(evidence: list[Evidence]) -> list[Evidence]:
    found: list[Evidence] = []
    seen: set[tuple[str, int, int, str]] = set()
    for item in evidence:
        key = (item.file, item.line_start, item.line_end, item.matched_pattern)
        if key not in seen:
            found.append(item)
            seen.add(key)
    return found
