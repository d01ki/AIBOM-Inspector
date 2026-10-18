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

from aibom.detectors.flow import is_potential
from aibom.exposure import ExposurePath, build_exposure_paths, prompt_slots
from aibom.impact import ImpactPath, build_impact_paths, build_unresolved_impacts
from aibom.models.analysis import Reachability
from aibom.models.entities import Agent, Entity, EntityType, Model, Package, Prompt, Service, Tool
from aibom.models.evidence import Evidence
from aibom.models.findings import Finding, Severity
from aibom.service import ScanResult


class DriftKind(str, Enum):
    """Stable machine-readable change categories."""

    EXPOSURE_ADDED = "exposure_added"
    EXPOSURE_REMOVED = "exposure_removed"
    IMPACT_PATH_ADDED = "impact_path_added"
    IMPACT_PATH_REMOVED = "impact_path_removed"
    IMPACT_PATH_CHANGED = "impact_path_changed"
    IMPACT_PATH_UNRESOLVED = "impact_path_unresolved"
    TOOL_REACHABILITY_ESCALATED = "tool_reachability_escalated"
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
    evidence_level: str | None = Field(
        default=None,
        description=(
            "For path changes: proven_static | potential | unknown. Independent of "
            "severity; an unknown change never gates."
        ),
    )
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def gates(self) -> bool:
        """Whether this change may fail a ``--fail-on`` gate."""
        return self.evidence_level != "unknown"


class BomComparison(BaseModel):
    """What "the AIBOM did not change" means for one comparison."""

    identical: bool
    compared_types: list[str] = Field(
        default_factory=list,
        description="Entity types compared (name, version and security metadata).",
    )
    excluded: list[str] = Field(
        default_factory=lambda: ["prompt (behavior; compared as exposure/impact paths)"],
    )
    baseline_components: int = 0
    candidate_components: int = 0
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)


class DriftReport(BaseModel):
    """Complete deterministic comparison of two scan results."""

    baseline_target: str
    candidate_target: str
    changes: list[DriftChange] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    kind_counts: dict[str, int] = Field(default_factory=dict)
    bom: BomComparison | None = None
    security_boundary_changed: bool = Field(
        default=False,
        description="A proven or potential exposure/impact path was added or changed.",
    )


def compare_scan_results(baseline: ScanResult, candidate: ScanResult) -> DriftReport:
    """Compare two scans, including trust-boundary and usage-state changes."""

    changes: list[DriftChange] = []
    changes.extend(_compare_impacts(baseline, candidate))
    changes.extend(_compare_exposures(baseline, candidate))
    changes.extend(_compare_prompts(baseline, candidate))
    changes.extend(_compare_entities(baseline, candidate))
    changes.extend(_compare_tools(baseline, candidate, changes))
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
        bom=compare_boms(baseline, candidate),
        security_boundary_changed=any(
            change.kind in _BOUNDARY_KINDS and change.gates for change in changes
        ),
    )


_BOUNDARY_KINDS = {
    DriftKind.EXPOSURE_ADDED,
    DriftKind.IMPACT_PATH_ADDED,
    DriftKind.IMPACT_PATH_CHANGED,
    DriftKind.TRUST_BOUNDARY_CHANGED,
    DriftKind.TOOL_REACHABILITY_ESCALATED,
}


def _compare_exposures(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    before = {path.prompt_anchor: path for path in build_exposure_paths(baseline.inventory)}
    after = _pair_relocated(
        before, {path.prompt_anchor: path for path in build_exposure_paths(candidate.inventory)}
    )
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
                evidence_level=_exposure_level(path),
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


def _pair_relocated(
    before: dict[str, ExposurePath], after: dict[str, ExposurePath]
) -> dict[str, ExposurePath]:
    """Re-key a candidate exposure whose sink only moved (file, function, lines).

    Two exposures with the same source kind, sink kind, trust boundary,
    privilege and models are the same exposure when neither has a slot match.
    """

    def key(path: ExposurePath) -> tuple[object, ...]:
        return (
            path.source_kind,
            path.sink_kind,
            path.trust_boundary,
            path.privileged,
            tuple(path.model_names),
        )

    unmatched_before = [anchor for anchor in sorted(before) if anchor not in after]
    rekeyed = dict(after)
    for anchor in sorted(after.keys() - before.keys()):
        match = next(
            (old for old in unmatched_before if key(before[old]) == key(after[anchor])), None
        )
        if match is None:
            continue
        unmatched_before.remove(match)
        rekeyed[match] = rekeyed.pop(anchor)
    return rekeyed


def _compare_impacts(
    baseline: ScanResult,
    candidate: ScanResult,
) -> list[DriftChange]:
    """Compare impact paths, matching first by prompt slot, then semantically.

    The prompt slot is line-insensitive; the semantic key additionally ignores
    which file and function the sink lives in.  A path whose sink moved to
    another file, or whose builder was renamed, is therefore the *same* path —
    not one removal plus one addition.
    """
    before_paths = build_impact_paths(baseline.inventory)
    after_paths = build_impact_paths(candidate.inventory)
    pairs, added, removed = _match_paths(before_paths, after_paths)
    changes: list[DriftChange] = []

    for path in added:
        changes.append(
            _change(
                DriftKind.IMPACT_PATH_ADDED,
                path.severity,
                _added_title(path),
                (
                    f"Untrusted {path.source_kind} can now reach privileged instructions "
                    f"for directly bound tool(s) {', '.join(path.tool_names)}, with potential "
                    f"to {path.consequence}."
                ),
                entity_type=EntityType.PROMPT.value,
                after_id=path.prompt_id,
                after_name=path.prompt_name,
                after_evidence=path.source_evidence,
                evidence_level=path.evidence_level,
                details=_impact_details(path),
            )
        )

    for path in removed:
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
                evidence_level=path.evidence_level,
                details=_impact_details(path),
            )
        )

    for old, new in pairs:
        if _impact_signature(old) == _impact_signature(new) and (
            old.evidence_level == new.evidence_level
        ):
            continue
        if _impact_signature(old) == _impact_signature(new):
            description = (
                f"The evidence for the path to {', '.join(new.tool_names)} changed from "
                f"{old.evidence_level} to {new.evidence_level}."
            )
        else:
            description = (
                f"The directly bound impact surface changed from "
                f"{', '.join(old.tool_names)} to {', '.join(new.tool_names)}."
            )
        changes.append(
            _change(
                DriftKind.IMPACT_PATH_CHANGED,
                new.severity,
                "Agent capability blast radius changed",
                description,
                entity_type=EntityType.PROMPT.value,
                before_id=old.prompt_id,
                after_id=new.prompt_id,
                before_name=old.prompt_name,
                after_name=new.prompt_name,
                before_evidence=old.source_evidence,
                after_evidence=new.source_evidence,
                evidence_level=new.evidence_level,
                details={
                    "before": _impact_details(old),
                    "after": _impact_details(new),
                },
            )
        )

    # Unresolved candidates: shown so silence is not read as safety, never gated.
    previous = [*before_paths, *build_unresolved_impacts(baseline.inventory)]
    known_before = {path.prompt_anchor for path in previous}
    known_semantic = {(path.sink_kind, _impact_signature(path)) for path in previous}
    for path in build_unresolved_impacts(candidate.inventory):
        if path.prompt_anchor in known_before or (
            (path.sink_kind, _impact_signature(path)) in known_semantic
        ):
            continue
        changes.append(
            _change(
                DriftKind.IMPACT_PATH_UNRESOLVED,
                Severity.INFO,
                "Unresolved input to a privileged prompt with a bound tool",
                (
                    f"{path.sink_kind} now drives bound tool(s) {', '.join(path.tool_names)} "
                    "but its input could not be resolved statically. This is not a proven "
                    "path and is not gated; review it manually."
                ),
                entity_type=EntityType.PROMPT.value,
                after_id=path.prompt_id,
                after_name=path.prompt_name,
                after_evidence=path.source_evidence,
                evidence_level=path.evidence_level,
                details=_impact_details(path),
            )
        )
    return changes


def _match_paths(
    before: list[ImpactPath], after: list[ImpactPath]
) -> tuple[list[tuple[ImpactPath, ImpactPath]], list[ImpactPath], list[ImpactPath]]:
    pairs: list[tuple[ImpactPath, ImpactPath]] = []
    after_by_anchor = {path.prompt_anchor: path for path in after}
    remaining_before: list[ImpactPath] = []
    used: set[str] = set()
    for path in before:
        match = after_by_anchor.get(path.prompt_anchor)
        if match is not None and match.id not in used:
            pairs.append((path, match))
            used.add(match.id)
        else:
            remaining_before.append(path)
    remaining_after = [path for path in after if path.id not in used]
    removed: list[ImpactPath] = []
    for path in remaining_before:
        match = next(
            (item for item in remaining_after if item.semantic_key == path.semantic_key), None
        )
        if match is None:
            removed.append(path)
            continue
        pairs.append((path, match))
        remaining_after.remove(match)
    return pairs, remaining_after, removed


def _added_title(path: ImpactPath) -> str:
    if path.evidence_level == "proven_static":
        return "New agent capability blast radius"
    return "New potential agent capability blast radius"


def compare_boms(baseline: ScanResult, candidate: ScanResult) -> BomComparison:
    """Whether the two component inventories are identical, and over what scope.

    Prompts are excluded on purpose: they are behavior, compared separately as
    exposure and impact paths.  Packages count whether or not they are AI
    packages, because a changed dependency is a changed BOM.
    """
    before = _component_signature(baseline)
    after = _component_signature(candidate)
    before_keys = {item[:2]: item for item in before}
    after_keys = {item[:2]: item for item in after}
    changed = sorted(
        key for key in before_keys.keys() & after_keys.keys() if before_keys[key] != after_keys[key]
    )
    return BomComparison(
        identical=before == after,
        compared_types=sorted({item[0] for item in [*before, *after]}),
        baseline_components=len(before),
        candidate_components=len(after),
        added=sorted(f"{kind}:{name}" for kind, name in after_keys.keys() - before_keys.keys()),
        removed=sorted(f"{kind}:{name}" for kind, name in before_keys.keys() - after_keys.keys()),
        changed=[f"{kind}:{name}" for kind, name in changed],
    )


def _component_signature(result: ScanResult) -> list[tuple[str, ...]]:
    signature: set[tuple[str, ...]] = set()
    for entity in result.inventory.entities:
        if isinstance(entity, Prompt):
            continue
        fields = _security_fields(entity)
        signature.add(
            (
                entity.type.value,
                entity.name.strip().lower(),
                str(getattr(entity, "version", "") or ""),
                repr(sorted(fields.items())),
            )
        )
    return sorted(signature)


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


def _exposure_level(path: ExposurePath) -> str:
    if is_potential(path.data_flow_path) or path.reachable is not Reachability.TRUE:
        return "potential"
    return "proven_static"


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
        "evidence_level": path.evidence_level,
        "impact_severity": (path.impact_severity or path.severity).value,
        "cross_file": path.cross_file,
        "semantic_key": path.semantic_key,
        "changed_boundary": (
            f"untrusted {path.source_kind} -> {path.sink_kind} ({path.trust_boundary})"
        ),
        "potential_consequence": path.consequence,
        "limitations": list(path.limitations),
        "nodes": [node.model_dump() for node in path.nodes],
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
    if isinstance(entity, Tool):
        # The tool's code, not its reachability: state is behavior and is
        # compared by `_compare_tools`, so an identical BOM stays identical.
        return {"framework": entity.framework, "capabilities": _tool_signature(entity)}
    return {}


def _tool_signature(tool: Tool) -> list[str]:
    return sorted(
        f"{item.kind}:{item.operation}:{','.join(item.controlled_parameters)}"
        for item in tool.capabilities
    )


def _compare_tools(
    baseline: ScanResult, candidate: ScanResult, earlier: list[DriftChange]
) -> list[DriftChange]:
    """A tool newly reachable from untrusted input, by registration or binding.

    Tools are matched by name and file, then by name and capability signature
    (so moving a tool is not a change).  A bound tool already reported as part
    of a new impact path is not reported twice.
    """
    before = [e for e in baseline.inventory.entities if isinstance(e, Tool)]
    after = [e for e in candidate.inventory.entities if isinstance(e, Tool)]
    covered = {
        name
        for change in earlier
        if change.kind is DriftKind.IMPACT_PATH_ADDED
        for name in change.details.get("tools", [])
    }
    by_key = {tool.natural_key(): tool for tool in before}
    by_shape = {(tool.tool_name, tuple(_tool_signature(tool))): tool for tool in before}
    changes: list[DriftChange] = []
    for tool in after:
        old = by_key.get(tool.natural_key()) or by_shape.get(
            (tool.tool_name, tuple(_tool_signature(tool)))
        )
        old_state = old.state if old is not None else "absent"
        if tool.state != "potentially_reachable" or old_state == tool.state:
            continue
        if tool.tool_name in covered:
            continue
        worst = max(
            (Severity(item.severity) for item in tool.capabilities),
            key=lambda item: item.rank,
            default=Severity.MEDIUM,
        )
        # Registration proves who chooses the arguments, not that an attack
        # works, so this never reaches Critical on its own.
        severity = Severity.HIGH if worst.rank >= Severity.HIGH.rank else Severity.MEDIUM
        operations = ", ".join(dict.fromkeys(item.impact for item in tool.capabilities))
        changes.append(
            _change(
                DriftKind.TOOL_REACHABILITY_ESCALATED,
                severity,
                "Tool newly reachable from untrusted input",
                (
                    f"{tool.framework or 'agent'} tool '{tool.tool_name}' moved from "
                    f"{old_state} to {tool.state}; a caller-controlled parameter can "
                    f"{operations or 'reach a recognized operation'}."
                ),
                entity_type=EntityType.TOOL.value,
                before_id=old.id if old is not None else None,
                after_id=tool.id,
                before_name=old.name if old is not None else None,
                after_name=tool.name,
                after_evidence=[
                    *tool.source_evidence,
                    *(e for item in tool.capabilities for e in item.source_evidence),
                ],
                evidence_level="proven_static",
                details={
                    "before_state": old_state,
                    "after_state": tool.state,
                    "trust_boundary": tool.trust_boundary,
                    "capabilities": _tool_signature(tool),
                },
            )
        )
    return changes


def _finding_key(finding: Finding) -> tuple[str, str]:
    return (finding.rule_id, finding.entity_name or finding.entity_id or "")


def _drift_finding(finding: Finding) -> bool:
    # These are represented more precisely by path-level changes.
    return finding.rule_id not in {"AIBOM-PROMPT-004", "AIBOM-IMPACT-001"}
