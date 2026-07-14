"""The Inventory — normalized, deduplicated set of entities and relationships.

Collectors emit raw entities; the Inventory merges them by natural key, unions
their evidence, and holds the typed relationship edges. This is the single
in-memory source of truth that the AIBOM, graph, and risk engines consume.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import TypeVar

from pydantic import BaseModel, Field, SerializeAsAny

from aibom.models.analysis import Reachability
from aibom.models.entities import Agent, Entity, EntityType, Model, Relationship, Service
from aibom.models.signals import RiskSignal

T = TypeVar("T")


class ScanMetadata(BaseModel):
    """Provenance for a scan run."""

    tool: str = "aibom"
    tool_version: str
    target: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScanStats(BaseModel):
    """What the scan actually did — proof of work for the UI and reports.

    A static scan is fast (it reads text, nothing more), which users can
    mistake for "it did nothing". These counters make the work inspectable.
    """

    files_scanned: int = Field(default=0, description="Files read line-by-line.")
    bytes_scanned: int = Field(default=0, description="Total size of the files read.")
    manifests_parsed: list[str] = Field(
        default_factory=list, description="Dependency manifests parsed (repo-relative)."
    )
    duration_ms: int | None = Field(default=None, description="Scan wall time (excl. clone).")
    clone_ms: int | None = Field(default=None, description="Clone wall time (API scans only).")
    detectors_run: list[str] = Field(
        default_factory=list, description="Detector IDs used during the scan."
    )
    parse_errors: list[str] = Field(
        default_factory=list,
        description="Files that required a legacy fallback because structured parsing failed.",
    )


class Inventory(BaseModel):
    """A normalized collection of AI supply-chain entities + relationships."""

    metadata: ScanMetadata
    # SerializeAsAny: dump each entity with its *runtime* class (Model, Package…),
    # not the base Entity schema — otherwise subclass fields (provider, ai, purl,
    # ecosystem, …) silently vanish from JSON output and the API payload.
    entities: list[SerializeAsAny[Entity]] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    signals: list[RiskSignal] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)

    def add_entity(self, entity: Entity) -> Entity:
        """Add an entity, merging evidence into any existing match by natural key.

        Returns the canonical entity that now lives in the inventory (either the
        pre-existing one, with evidence unioned in, or the newly added one).
        """
        for existing in self.entities:
            if existing.natural_key() == entity.natural_key():
                _merge_entity(existing, entity)
                return existing
        self.entities.append(entity)
        return entity

    def add_relationship(self, relationship: Relationship) -> None:
        """Add an edge, deduplicating on (source, target, type)."""
        for existing in self.relationships:
            if (
                existing.source_id == relationship.source_id
                and existing.target_id == relationship.target_id
                and existing.relationship == relationship.relationship
            ):
                existing.source_evidence.extend(relationship.source_evidence)
                return
        self.relationships.append(relationship)

    def add_signal(self, signal: RiskSignal) -> None:
        """Add a risk signal, deduplicating on (kind, file, line)."""
        key = signal.location_key()
        if any(s.location_key() == key for s in self.signals):
            return
        self.signals.append(signal)

    def signals_of(self, kind: str) -> list[RiskSignal]:
        """Return all risk signals of a given kind."""
        return [s for s in self.signals if s.kind == kind]

    def by_type(self, entity_type: EntityType) -> list[Entity]:
        """Return all entities of a given type."""
        return [e for e in self.entities if e.type == entity_type]

    def has_ai_components(self) -> bool:
        """True if anything AI-related was found.

        Non-AI packages are part of the complete BOM but do not count as AI
        usage — a repo whose only hits are ordinary dependencies should read
        as "no AI components detected", not be scored.
        """
        return any(
            e.type != EntityType.PACKAGE or bool(getattr(e, "ai", False)) for e in self.entities
        )

    def counts(self) -> dict[str, int]:
        """Return a {type: count} summary."""
        result: dict[str, int] = {}
        for entity in self.entities:
            result[entity.type.value] = result.get(entity.type.value, 0) + 1
        return result


def _merge_evidence(into: Entity, other: Entity) -> None:
    """Union ``other``'s evidence into ``into`` without duplicating locations."""
    seen = {(e.file, e.line_start, e.line_end, e.matched_pattern) for e in into.source_evidence}
    for ev in other.source_evidence:
        key = (ev.file, ev.line_start, ev.line_end, ev.matched_pattern)
        if key not in seen:
            into.source_evidence.append(ev)
            seen.add(key)


def _merge_entity(into: Entity, other: Entity) -> None:
    """Merge additive detector analysis without changing the stable natural key."""
    _merge_evidence(into, other)
    _extend_unique(into.detector_ids, other.detector_ids)
    _extend_unique(into.source_contexts, other.source_contexts)
    _extend_unique(into.reachability_path, other.reachability_path)

    seen_steps = {
        (s.file, s.line, s.column, s.symbol, s.value, s.operation) for s in into.resolution_path
    }
    for step in other.resolution_path:
        key = (step.file, step.line, step.column, step.symbol, step.value, step.operation)
        if key not in seen_steps:
            into.resolution_path.append(step)
            seen_steps.add(key)

    into.usage.declared = into.usage.declared or other.usage.declared
    into.usage.imported = into.usage.imported or other.usage.imported
    into.usage.instantiated = into.usage.instantiated or other.usage.instantiated
    into.usage.invoked = into.usage.invoked or other.usage.invoked
    into.usage.runtime_observed = into.usage.runtime_observed or other.usage.runtime_observed
    into.usage.reachable = _merge_reachability(into.usage.reachable, other.usage.reachable)

    for field in type(into.confidence_factors).model_fields:
        current = getattr(into.confidence_factors, field)
        candidate = getattr(other.confidence_factors, field)
        setattr(into.confidence_factors, field, max(current, candidate))

    if (
        other.value_resolution.value == "resolved"
        or into.value_resolution.value == "not_applicable"
    ):
        into.value_resolution = other.value_resolution

    if isinstance(into, Model) and isinstance(other, Model):
        into.provider = into.provider or other.provider
        into.revision = into.revision or other.revision
        into.revision_pinned = into.revision_pinned or other.revision_pinned
        into.environment_variable = into.environment_variable or other.environment_variable
        _extend_unique(into.formats, other.formats)
    elif isinstance(into, Service) and isinstance(other, Service):
        into.endpoint = into.endpoint or other.endpoint
    elif isinstance(into, Agent) and isinstance(other, Agent):
        into.framework = into.framework or other.framework
        _extend_unique(into.tools, other.tools)
        _extend_unique(into.model_refs, other.model_refs)


def _merge_reachability(left: Reachability, right: Reachability) -> Reachability:
    if Reachability.TRUE in {left, right}:
        return Reachability.TRUE
    if Reachability.UNKNOWN in {left, right}:
        return Reachability.UNKNOWN
    return Reachability.FALSE


def _extend_unique(target: list[T], values: Iterable[T]) -> None:
    for value in values:
        if value not in target:
            target.append(value)
