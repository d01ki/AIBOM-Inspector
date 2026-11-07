"""The Inventory — normalized, deduplicated set of entities and relationships.

Collectors emit raw entities; the Inventory merges them by natural key, unions
their evidence, and holds the typed relationship edges. This is the single
in-memory source of truth that the AIBOM, graph, and risk engines consume.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import TypeVar

from pydantic import BaseModel, Field, PrivateAttr, SerializeAsAny

from aibom.models.analysis import Reachability, ResolutionStep
from aibom.models.entities import (
    Agent,
    DependencyScope,
    Entity,
    EntityType,
    Model,
    Package,
    Prompt,
    Relationship,
    Service,
)
from aibom.models.signals import RiskSignal

T = TypeVar("T")


class ScanMetadata(BaseModel):
    """Provenance for a scan run."""

    tool: str = "aibom"
    tool_version: str
    target: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ref: str | None = Field(default=None, description="Requested branch, tag, or commit.")
    commit: str | None = Field(
        default=None, description="Commit the scanned checkout was at, read from .git."
    )
    source_url_template: str | None = Field(
        default=None,
        description="URL with {path} and {line} placeholders, pinned to `commit`.",
    )


class VulnLookup(BaseModel):
    """What the known-vulnerability lookup did, so a failed or partial lookup
    is never read as "no vulnerabilities"."""

    requested: bool = False
    source: str = "osv.dev"
    status: str = Field(
        default="not_requested",
        description="not_requested | complete | partial | failed",
    )
    queried: int = Field(default=0, description="Packages whose exact version was looked up.")
    failed: int = Field(default=0, description="Lookups that errored (network, timeout).")
    not_queried_unpinned: int = Field(
        default=0, description="Packages without an exact version, so not looked up."
    )
    not_queried_over_limit: int = Field(
        default=0, description="Pinned packages skipped by the per-scan query cap."
    )
    errors: list[str] = Field(default_factory=list)


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
    vuln_lookup: VulnLookup = Field(default_factory=VulnLookup)


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

    # Natural key -> entity, so merging stays O(1) per add. A lockfile can
    # contribute thousands of components; a linear scan per add would make the
    # inventory quadratic in the size of the dependency graph.
    _index: dict[tuple[str, str], Entity] = PrivateAttr(default_factory=dict)
    _indexed: tuple[int, int] = PrivateAttr(default=(0, 0))
    _rel_index: dict[tuple[str, str, str], Relationship] = PrivateAttr(default_factory=dict)
    _rel_indexed: tuple[int, int] = PrivateAttr(default=(0, 0))

    def add_entity(self, entity: Entity) -> Entity:
        """Add an entity, merging evidence into any existing match by natural key.

        Returns the canonical entity that now lives in the inventory (either the
        pre-existing one, with evidence unioned in, or the newly added one).
        """
        index = self._entity_index()
        key = entity.natural_key()
        existing = index.get(key)
        if existing is not None:
            _merge_entity(existing, entity)
            return existing
        self.entities.append(entity)
        index[key] = entity
        self._indexed = (id(self.entities), len(self.entities))
        return entity

    def _entity_index(self) -> dict[tuple[str, str], Entity]:
        """The dedupe index, rebuilt if ``entities`` was replaced or filtered."""
        stamp = (id(self.entities), len(self.entities))
        if stamp != self._indexed:
            self._index = {e.natural_key(): e for e in self.entities}
            self._indexed = stamp
        return self._index

    def add_relationship(self, relationship: Relationship) -> None:
        """Add an edge, deduplicating on (source, target, type)."""
        stamp = (id(self.relationships), len(self.relationships))
        if stamp != self._rel_indexed:
            # Rebuilt if ``relationships`` was replaced or filtered elsewhere.
            self._rel_index = {}
            for rel in self.relationships:
                self._rel_index.setdefault(_rel_key(rel), rel)
        key = _rel_key(relationship)
        existing = self._rel_index.get(key)
        if existing is not None:
            existing.source_evidence.extend(relationship.source_evidence)
        else:
            self.relationships.append(relationship)
            self._rel_index[key] = relationship
        self._rel_indexed = (id(self.relationships), len(self.relationships))

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


#: Lockfile formats that record each package's own dependencies. Pipfile.lock
#: and hash-pinned requirements pin versions but do not say who needs whom.
GRAPH_LOCKFILES = frozenset({
    "package-lock.json", "poetry.lock", "uv.lock", "cargo.lock", "composer.lock",
    "gemfile.lock",
})


def dependencies_resolved(entity: Entity) -> bool:
    """True when the scan knows this package's own dependencies.

    A package seen only in a manifest (or in a lockfile that does not record
    edges) has *unknown* dependencies; an empty list for it would be a false
    claim that it is a leaf. Non-package components are judged by the linker,
    which only emits proven edges, so for them an empty list is a statement.
    """
    if not isinstance(entity, Package):
        return True
    return any(
        ev.kind == "lockfile" and ev.file.replace("\\", "/").rsplit("/", 1)[-1].lower()
        in GRAPH_LOCKFILES
        for ev in entity.source_evidence
    )


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
    elif isinstance(into, Package) and isinstance(other, Package):
        # A lockfile resolves what a manifest only constrains: an exact pin
        # always beats a range, whichever collector saw the package first.
        if other.version_pinned and not into.version_pinned:
            into.version = other.version
            into.version_pinned = True
        else:
            into.version = into.version or other.version
        if DependencyScope.DIRECT in {into.dependency_scope, other.dependency_scope}:
            into.dependency_scope = DependencyScope.DIRECT
        into.license = into.license or other.license
        into.producer = into.producer or other.producer
        into.producer_url = into.producer_url or other.producer_url
        if into.content_hash is None and other.content_hash is not None:
            into.content_hash = other.content_hash
            into.hash_algorithm = other.hash_algorithm
            into.hash_artifact = other.hash_artifact
        into.ai = into.ai or other.ai
    elif isinstance(into, Prompt) and isinstance(other, Prompt):
        into.content_hash = into.content_hash or other.content_hash
        into.source_kind = into.source_kind or other.source_kind
        into.sink_kind = into.sink_kind or other.sink_kind
        into.trust_boundary = into.trust_boundary or other.trust_boundary
        into.user_controlled = _merge_user_controlled(
            into.user_controlled, other.user_controlled
        )
        _extend_unique(into.model_refs, other.model_refs)
        _extend_unique(into.tool_refs, other.tool_refs)
        _extend_unique(into.capabilities, other.capabilities)
        _merge_steps(into.data_flow_path, other.data_flow_path)


def _merge_reachability(left: Reachability, right: Reachability) -> Reachability:
    if Reachability.TRUE in {left, right}:
        return Reachability.TRUE
    if Reachability.UNKNOWN in {left, right}:
        return Reachability.UNKNOWN
    return Reachability.FALSE


def _merge_user_controlled(left: bool | None, right: bool | None) -> bool | None:
    if True in {left, right}:
        return True
    if False in {left, right}:
        return False
    return None


def _merge_steps(target: list[ResolutionStep], values: Iterable[ResolutionStep]) -> None:
    seen = {(s.file, s.line, s.column, s.symbol, s.value, s.operation) for s in target}
    for step in values:
        key = (step.file, step.line, step.column, step.symbol, step.value, step.operation)
        if key not in seen:
            target.append(step)
            seen.add(key)


def _extend_unique(target: list[T], values: Iterable[T]) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def _rel_key(rel: Relationship) -> tuple[str, str, str]:
    return (rel.source_id, rel.target_id, rel.relationship.value)
