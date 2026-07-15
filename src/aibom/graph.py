"""Dependency-graph builder.

Projects an :class:`~aibom.inventory.Inventory` plus its risk findings into a
plain ``{nodes, edges}`` structure suitable for visualization: every entity is a
node tagged with its worst finding severity, and every (validated) relationship
is a typed edge. Kept dependency-free — no graph library — because MVP graphs
are small and this must serialize straight to JSON for the API and web UI.
"""

from __future__ import annotations

from typing import Any

from aibom.inventory import Inventory
from aibom.models.findings import Finding, Severity


def build_graph(inventory: Inventory, findings: list[Finding]) -> dict[str, Any]:
    """Return ``{"nodes": [...], "edges": [...]}`` for the inventory."""
    worst: dict[str, Severity] = {}
    counts: dict[str, int] = {}
    for f in findings:
        if f.entity_id is None:
            continue
        counts[f.entity_id] = counts.get(f.entity_id, 0) + 1
        current = worst.get(f.entity_id)
        if current is None or f.severity.rank > current.rank:
            worst[f.entity_id] = f.severity

    nodes: list[dict[str, Any]] = []
    for e in inventory.entities:
        sev = worst.get(e.id)
        # Keep the graph readable: plain (non-AI) dependencies only appear when
        # something is wrong with them; the full list lives in the inventory.
        if e.type.value == "package" and not bool(getattr(e, "ai", False)) and sev is None:
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

    known = {e.id for e in inventory.entities}
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for r in inventory.relationships:
        if r.source_id not in known or r.target_id not in known:
            continue
        key = (r.source_id, r.target_id, r.relationship.value)
        if key in seen:
            continue
        seen.add(key)
        edges.append({"source": r.source_id, "target": r.target_id, "type": r.relationship.value})

    return {"nodes": nodes, "edges": edges}
