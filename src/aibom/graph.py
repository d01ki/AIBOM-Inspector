"""Dependency-graph builder.

Projects an :class:`~aibom.inventory.Inventory` plus its risk findings into a
plain ``{nodes, edges}`` structure suitable for visualization: every entity is a
node tagged with its worst finding severity, and every (validated) relationship
is a typed edge. Kept dependency-free — no graph library — because MVP graphs
are small and this must serialize straight to JSON for the API and web UI.
"""

from __future__ import annotations

from typing import Any

from aibom.exposure import build_exposure_paths
from aibom.impact import build_impact_paths
from aibom.inventory import Inventory
from aibom.models.entities import RelationshipType
from aibom.models.findings import Finding, Severity
from aibom.policy import production_view


def build_graph(inventory: Inventory, findings: list[Finding]) -> dict[str, Any]:
    """Return ``{"nodes": [...], "edges": [...]}`` for the inventory."""
    inventory = production_view(inventory)
    worst: dict[str, Severity] = {}
    counts: dict[str, int] = {}
    for f in findings:
        if f.entity_id is None:
            continue
        counts[f.entity_id] = counts.get(f.entity_id, 0) + 1
        current = worst.get(f.entity_id)
        if current is None or f.severity.rank > current.rank:
            worst[f.entity_id] = f.severity

    # Keep the graph readable: a plain (non-AI) dependency appears only when
    # something is wrong with it or an AI package depends on it directly — one
    # hop, so a large lockfile does not flood the map. The full list lives in
    # the inventory.
    ai_packages = {
        e.id
        for e in inventory.entities
        if e.type.value == "package" and bool(getattr(e, "ai", False))
    }
    pulled_in = {
        r.target_id
        for r in inventory.relationships
        if r.relationship is RelationshipType.DEPENDS_ON and r.source_id in ai_packages
    }

    nodes: list[dict[str, Any]] = []
    for e in inventory.entities:
        sev = worst.get(e.id)
        if (
            e.type.value == "package"
            and e.id not in ai_packages
            and sev is None
            and e.id not in pulled_in
        ):
            continue
        location = e.source_evidence[0].location() if e.source_evidence else None
        nodes.append(
            {
                "id": e.id,
                "label": e.name,
                "type": e.type.value,
                "provider": (
                    getattr(e, "provider", None)
                    or getattr(e, "source", None)
                    or getattr(e, "source_kind", None)
                ),
                "severity": sev.value if sev else None,
                "finding_count": counts.get(e.id, 0),
                "location": location,
                "detectors": sorted(e.detector_ids),
                "usage": e.usage.model_dump(mode="json"),
                "source_contexts": sorted(context.value for context in e.source_contexts),
            }
        )

    # Only edges between drawn nodes: an edge into a hidden package would point
    # at nothing in the UI.
    known = {n["id"] for n in nodes}
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for r in inventory.relationships:
        if r.source_id not in known or r.target_id not in known:
            continue
        key = (r.source_id, r.target_id, r.relationship.value)
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            {
                "source": r.source_id,
                "target": r.target_id,
                "type": r.relationship.value,
                "evidence": [ev.location() for ev in r.source_evidence],
            }
        )

    exposure_paths = [
        path.model_dump(mode="json") for path in build_exposure_paths(inventory)
    ]
    impact_paths = [
        path.model_dump(mode="json") for path in build_impact_paths(inventory)
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "exposure_paths": exposure_paths,
        "impact_paths": impact_paths,
    }
