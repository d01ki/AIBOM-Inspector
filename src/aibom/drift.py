"""Security-significant drift between two evidence-backed AIBOM scans.

Traditional BOM diffs answer whether a component was added or removed.  This
module also compares *behavioral context*: a prompt becoming user-controlled,
crossing a new trust boundary, changing its model target, or moving from merely
declared to invoked/reachable usage.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from aibom.exposure import ExposurePath, build_exposure_paths, prompt_slots
from aibom.impact import ImpactPath, build_impact_paths
from aibom.models.entities import Agent, Entity, EntityType, Model, Package, Prompt, Service
from aibom.models.evidence import Evidence
from aibom.models.findings import Finding, Severity
from aibom.service import ScanResult


class DriftKind(str, Enum):
    """Stable machine-readable change categories."""

    EXPOSURE_ADDED = "exposure_added"
    EXPOSURE_REMOVED = "exposure_removed"
    IMPACT_PATH_ADDED = "impact_path_added"
    IMPACT_PATH_REMOVED = "impact_path_removed"
    PROMPT_CONTENT_CHANGED = "prompt_content_changed"
    PROMPT_TARGET_CHANGED = "prompt_target_changed"
    TRUST_BOUNDARY_CHANGED = "trust_boundary_changed"
    USAGE_ESCALATED = "usage_escalated"
    COMPONENT_ADDED = "component_added"
    COMPONENT_REMOVED = "component_removed"
    COMPONENT_CHANGED = "component_changed"
    FINDING_ADDED = "finding_added"
    FINDING_RESOLVED = "finding_resolved"


class DriftChange(BaseModel):
    """One auditable change between the baseline and candidate scan."""

    id: str
    kind: DriftKind
    severity: Severity
    title: str
    description: str
    entity_type: str | None = None
    before_id: str | None = None
    after_id: str | None = None
    before_name: str | None = None
    after_name: str | None = None
    before_evidence: list[Evidence] = Field(default_factory=list)
    after_evidence: list[Evidence] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class DriftReport(BaseModel):
    """Complete deterministic comparison of two scan results."""

    baseline_target: str
    candidate_target: str
    changes: list[DriftChange] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    kind_counts: dict[str, int] = Field(default_factory=dict)


def compare_scan_results(baseline: ScanResult, candidate: ScanResult) -> DriftReport:
    """Compare two scans, including trust-boundary and usage-state changes."""

    changes: list[DriftChange] = []
    changes.extend(_compare_impacts(baseline, candidate))
    changes.extend(_compare_exposures(baseline, candidate))
    changes.extend(_compare_prompts(baseline, candidate))
    changes.extend(_compare_entities(baseline, candidate))
    changes.extend(_compare_findings(baseline, candidate))
    changes.sort(key=lambda change: (-change.severity.rank, change.kind.value, change.id))

    severity_counts = {severity.value: 0 for severity in Severity}
    kind_counts = {kind.value: 0 for kind in DriftKind}
    for change in changes:
        severity_counts[change.severity.value] += 1
        kind_counts[change.kind.value] += 1

    return DriftReport(
        baseline_target=baseline.inventory.metadata.target,
        candidate_target=candidate.inventory.metadata.target,
        changes=changes,
        severity_counts=severity_counts,
        kind_counts=kind_counts,
    )


def _compare_exposures(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    before = {path.prompt_anchor: path for path in build_exposure_paths(baseline.inventory)}
    after = {path.prompt_anchor: path for path in build_exposure_paths(candidate.inventory)}
    changes: list[DriftChange] = []

    for anchor in sorted(after.keys() - before.keys()):
        path = after[anchor]
        severity = Severity.HIGH if path.privileged else Severity.INFO
        description = (
            f"Untrusted {path.source_kind} now reaches {path.sink_kind}"
            f"{_model_suffix(path)} across {path.trust_boundary}."
        )
        changes.append(
            _change(
                DriftKind.EXPOSURE_ADDED,
                severity,
                "New privileged prompt exposure"
                if path.privileged
                else "New untrusted prompt input path",
                description,
                entity_type=EntityType.PROMPT.value,
                after_id=path.prompt_id,
                after_name=path.prompt_name,
                after_evidence=path.source_evidence,
                details=_exposure_details(path),
            )
        )

    for anchor in sorted(before.keys() - after.keys()):
        path = before[anchor]
        changes.append(
            _change(
                DriftKind.EXPOSURE_REMOVED,
                Severity.INFO,
                "Prompt exposure removed",
                f"The previous {path.source_kind} -> {path.sink_kind} path is no longer proven.",
                entity_type=EntityType.PROMPT.value,
                before_id=path.prompt_id,
                before_name=path.prompt_name,
                before_evidence=path.source_evidence,
                details=_exposure_details(path),
            )
        )

    for anchor in sorted(before.keys() & after.keys()):
        old, new = before[anchor], after[anchor]
        if old.trust_boundary != new.trust_boundary:
            changes.append(
                _change(
                    DriftKind.TRUST_BOUNDARY_CHANGED,
                    Severity.MEDIUM,
                    "Prompt trust boundary changed",
                    f"Trust boundary changed from {old.trust_boundary} "
                    f"to {new.trust_boundary}.",
                    entity_type=EntityType.PROMPT.value,
                    before_id=old.prompt_id,
                    after_id=new.prompt_id,
                    before_name=old.prompt_name,
                    after_name=new.prompt_name,
                    before_evidence=old.source_evidence,
                    after_evidence=new.source_evidence,
                    details={
                        "before_trust_boundary": old.trust_boundary,
                        "after_trust_boundary": new.trust_boundary,
                    },
                )
            )
    return changes


def _compare_impacts(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    before = {path.prompt_anchor: path for path in build_impact_paths(baseline.inventory)}
    after = {path.prompt_anchor: path for path in build_impact_paths(candidate.inventory)}
    changes: list[DriftChange] = []

    for anchor in sorted(after.keys() - before.keys()):
        path = after[anchor]
        changes.append(
            _change(
                DriftKind.IMPACT_PATH_ADDED,
                path.severity,
                "New agent capability blast radius",
                (
                    f"Untrusted {path.source_kind} can now reach privileged instructions "
                    f"for directly bound tool(s) {', '.join(path.tool_names)}, with potential "
                    f"to {path.consequence}."
                ),
                entity_type=EntityType.PROMPT.value,
                after_id=path.prompt_id,
                after_name=path.prompt_name,
                after_evidence=path.source_evidence,
                details=_impact_details(path),
            )
        )

    for anchor in sorted(before.keys() - after.keys()):
        path = before[anchor]
        changes.append(
            _change(
                DriftKind.IMPACT_PATH_REMOVED,
                Severity.INFO,
                "Agent capability blast radius removed",
                (
                    f"The previous prompt-to-tool path for "
                    f"{', '.join(path.tool_names)} is no longer proven."
                ),
                entity_type=EntityType.PROMPT.value,
                before_id=path.prompt_id,
                before_name=path.prompt_name,
                before_evidence=path.source_evidence,
                details=_impact_details(path),
            )
        )

    for anchor in sorted(before.keys() & after.keys()):
        old, new = before[anchor], after[anchor]
        old_signature = _impact_signature(old)
        new_signature = _impact_signature(new)
        if old_signature == new_signature:
            continue
        changes.append(
            _change(
                DriftKind.IMPACT_PATH_ADDED,
                new.severity,
                "Agent capability blast radius changed",
                (
                    f"The directly bound impact surface changed from "
                    f"{', '.join(old.tool_names)} to {', '.join(new.tool_names)}."
                ),
                entity_type=EntityType.PROMPT.value,
                before_id=old.prompt_id,
                after_id=new.prompt_id,
                before_name=old.prompt_name,
                after_name=new.prompt_name,
                before_evidence=old.source_evidence,
                after_evidence=new.source_evidence,
                details={
                    "before": _impact_details(old),
                    "after": _impact_details(new),
                },
            )
        )
    return changes


def _compare_prompts(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    before = {slot.anchor: slot.prompt for slot in prompt_slots(baseline.inventory)}
    after = {slot.anchor: slot.prompt for slot in prompt_slots(candidate.inventory)}
    changes: list[DriftChange] = []
    for anchor in sorted(before.keys() & after.keys()):
        old, new = before[anchor], after[anchor]
        common = {
            "entity_type": EntityType.PROMPT.value,
            "before_id": old.id,
            "after_id": new.id,
            "before_name": old.name,
            "after_name": new.name,
            "before_evidence": old.source_evidence,
            "after_evidence": new.source_evidence,
        }
        if old.content_hash and new.content_hash and old.content_hash != new.content_hash:
            changes.append(
                _change(
                    DriftKind.PROMPT_CONTENT_CHANGED,
                    Severity.LOW,
                    "Prompt content changed",
                    "A statically resolved prompt changed; only its hashes are retained.",
                    details={
                        "before_hash": old.content_hash,
                        "after_hash": new.content_hash,
                    },
                    **common,
                )
            )
        if sorted(old.model_refs) != sorted(new.model_refs):
            changes.append(
                _change(
                    DriftKind.PROMPT_TARGET_CHANGED,
                    Severity.MEDIUM,
                    "Prompt model target changed",
                    "The model consuming this prompt changed.",
                    details={
                        "before_models": sorted(old.model_refs),
                        "after_models": sorted(new.model_refs),
                    },
                    **common,
                )
            )
    return changes


def _compare_entities(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    before = {
        entity.natural_key(): entity
        for entity in baseline.inventory.entities
        if not isinstance(entity, Prompt) and _ai_relevant(entity)
    }
    after = {
        entity.natural_key(): entity
        for entity in candidate.inventory.entities
        if not isinstance(entity, Prompt) and _ai_relevant(entity)
    }
    changes: list[DriftChange] = []

    for key in sorted(after.keys() - before.keys()):
        entity = after[key]
        changes.append(
            _change(
                DriftKind.COMPONENT_ADDED,
                Severity.LOW,
                "AI component added",
                f"'{entity.name}' is new in the candidate AIBOM.",
                entity_type=entity.type.value,
                after_id=entity.id,
                after_name=entity.name,
                after_evidence=entity.source_evidence,
            )
        )
    for key in sorted(before.keys() - after.keys()):
        entity = before[key]
        changes.append(
            _change(
                DriftKind.COMPONENT_REMOVED,
                Severity.INFO,
                "AI component removed",
                f"'{entity.name}' is no longer present in the candidate AIBOM.",
                entity_type=entity.type.value,
                before_id=entity.id,
                before_name=entity.name,
                before_evidence=entity.source_evidence,
            )
        )
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        old_state, old_rank = _usage_state(old)
        new_state, new_rank = _usage_state(new)
        if new_rank > old_rank:
            severity = Severity.MEDIUM if new_rank >= 4 else Severity.LOW
            changes.append(
                _change(
                    DriftKind.USAGE_ESCALATED,
                    severity,
                    "AI component usage escalated",
                    f"'{new.name}' moved from {old_state} to {new_state}.",
                    entity_type=new.type.value,
                    before_id=old.id,
                    after_id=new.id,
                    before_name=old.name,
                    after_name=new.name,
                    before_evidence=old.source_evidence,
                    after_evidence=new.source_evidence,
                    details={"before_usage": old_state, "after_usage": new_state},
                )
            )

        old_fields = _security_fields(old)
        new_fields = _security_fields(new)
        if old_fields != new_fields:
            changes.append(
                _change(
                    DriftKind.COMPONENT_CHANGED,
                    Severity.MEDIUM,
                    "AI component security metadata changed",
                    "Version, revision, endpoint, or capability metadata changed "
                    f"for '{new.name}'.",
                    entity_type=new.type.value,
                    before_id=old.id,
                    after_id=new.id,
                    before_name=old.name,
                    after_name=new.name,
                    before_evidence=old.source_evidence,
                    after_evidence=new.source_evidence,
                    details={"before": old_fields, "after": new_fields},
                )
            )
    return changes


def _compare_findings(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    before = {_finding_key(item): item for item in baseline.findings if _drift_finding(item)}
    after = {_finding_key(item): item for item in candidate.findings if _drift_finding(item)}
    changes: list[DriftChange] = []
    for key in sorted(after.keys() - before.keys()):
        finding = after[key]
        changes.append(
            _change(
                DriftKind.FINDING_ADDED,
                finding.severity,
                "New risk finding",
                f"{finding.rule_id}: {finding.title}",
                after_id=finding.entity_id,
                after_name=finding.entity_name,
                after_evidence=finding.source_evidence,
                details={"rule_id": finding.rule_id},
            )
        )
    for key in sorted(before.keys() - after.keys()):
        finding = before[key]
        changes.append(
            _change(
                DriftKind.FINDING_RESOLVED,
                Severity.INFO,
                "Risk finding resolved",
                f"{finding.rule_id}: {finding.title}",
                before_id=finding.entity_id,
                before_name=finding.entity_name,
                before_evidence=finding.source_evidence,
                details={"rule_id": finding.rule_id},
            )
        )
    return changes


def _change(
    kind: DriftKind,
    severity: Severity,
    title: str,
    description: str,
    **kwargs: Any,
) -> DriftChange:
    identity = "\x1f".join(
        (
            kind.value,
            str(kwargs.get("before_id") or ""),
            str(kwargs.get("after_id") or ""),
            str(kwargs.get("before_name") or ""),
            str(kwargs.get("after_name") or ""),
            description,
        )
    )
    return DriftChange(
        id=f"drift:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}",
        kind=kind,
        severity=severity,
        title=title,
        description=description,
        **kwargs,
    )


def _model_suffix(path: ExposurePath) -> str:
    return f" and model(s) {', '.join(path.model_names)}" if path.model_names else ""


def _exposure_details(path: ExposurePath) -> dict[str, Any]:
    return {
        "path_id": path.id,
        "prompt_anchor": path.prompt_anchor,
        "source_kind": path.source_kind,
        "sink_kind": path.sink_kind,
        "trust_boundary": path.trust_boundary,
        "privileged": path.privileged,
        "models": path.model_names,
        "reachable": path.reachable.value,
        "confidence": path.confidence,
        "flow_operations": [step.operation for step in path.data_flow_path],
    }


def _impact_details(path: ImpactPath) -> dict[str, Any]:
    return {
        "path_id": path.id,
        "exposure_path_id": path.exposure_path_id,
        "prompt_anchor": path.prompt_anchor,
        "source_kind": path.source_kind,
        "sink_kind": path.sink_kind,
        "trust_boundary": path.trust_boundary,
        "models": path.model_names,
        "tools": path.tool_names,
        "severity": path.severity.value,
        "reachable": path.reachable.value,
        "confidence": path.confidence,
        "binding": path.binding,
        "capabilities": [
            {
                "tool": item.tool_name,
                "kind": item.kind,
                "operation": item.operation,
                "impact": item.impact,
                "controlled_parameters": item.controlled_parameters,
            }
            for item in path.capabilities
        ],
    }


def _impact_signature(
    path: ImpactPath,
) -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    return tuple(
        sorted(
            (
                item.tool_name,
                item.kind,
                item.operation,
                tuple(item.controlled_parameters),
            )
            for item in path.capabilities
        )
    )


def _ai_relevant(entity: Entity) -> bool:
    return not isinstance(entity, Package) or entity.ai


def _usage_state(entity: Entity) -> tuple[str, int]:
    usage = entity.usage
    if usage.runtime_observed:
        return ("runtime_observed", 6)
    if usage.reachable.value == "true":
        return ("reachable", 5)
    if usage.invoked:
        return ("invoked", 4)
    if usage.instantiated:
        return ("instantiated", 3)
    if usage.imported:
        return ("imported", 2)
    if usage.declared:
        return ("declared", 1)
    return ("unknown", 0)


def _security_fields(entity: Entity) -> dict[str, Any]:
    if isinstance(entity, Model):
        return {
            "provider": entity.provider,
            "revision": entity.revision,
            "revision_pinned": entity.revision_pinned,
            "formats": sorted(entity.formats),
        }
    if isinstance(entity, Package):
        return {
            "ecosystem": entity.ecosystem,
            "version": entity.version,
            "version_pinned": entity.version_pinned,
        }
    if isinstance(entity, Service):
        return {"kind": entity.kind, "endpoint": entity.endpoint}
    if isinstance(entity, Agent):
        return {
            "framework": entity.framework,
            "tools": sorted(entity.tools),
            "model_refs": sorted(entity.model_refs),
        }
    return {}


def _finding_key(finding: Finding) -> tuple[str, str]:
    return (finding.rule_id, finding.entity_name or finding.entity_id or "")


def _drift_finding(finding: Finding) -> bool:
    # These are represented more precisely by path-level changes.
    return finding.rule_id not in {"AIBOM-PROMPT-004", "AIBOM-IMPACT-001"}
