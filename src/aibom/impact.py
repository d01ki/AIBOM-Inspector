"""Evidence-backed blast-radius paths for tool-using AI agents.

An impact path is deliberately stricter than co-location.  It exists only when
the prompt lineage proves untrusted input reaches privileged instructions and
the same agent constructor directly binds a decorated tool whose body contains
a recognized security-relevant operation.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from aibom.exposure import build_exposure_paths
from aibom.inventory import Inventory
from aibom.models.analysis import Reachability
from aibom.models.entities import Prompt, ToolCapability
from aibom.models.evidence import Evidence
from aibom.models.findings import Severity


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
        capabilities = sorted(
            (item.model_copy(deep=True) for item in prompt.capabilities),
            key=lambda item: (item.tool_name, item.kind, item.operation),
        )
        severity = max(
            (Severity(item.severity) for item in capabilities),
            key=lambda item: item.rank,
        )
        tool_names = sorted({item.tool_name for item in capabilities})
        signature = "\x1f".join(
            (
                f"{item.tool_name}:{item.kind}:{item.operation}:"
                f"{','.join(item.controlled_parameters)}"
            )
            for item in capabilities
        )
        identity = "\x1f".join((exposure.id, signature))
        evidence = [item.model_copy() for item in exposure.source_evidence]
        for capability in capabilities:
            evidence.extend(item.model_copy() for item in capability.source_evidence)
        confidence = min((item.confidence for item in evidence), default=0.0)
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
            )
        )
    return sorted(paths, key=lambda path: (-path.severity.rank, path.id))


def _dedupe_evidence(evidence: list[Evidence]) -> list[Evidence]:
    found: list[Evidence] = []
    seen: set[tuple[str, int, int, str]] = set()
    for item in evidence:
        key = (item.file, item.line_start, item.line_end, item.matched_pattern)
        if key not in seen:
            found.append(item)
            seen.add(key)
    return found
