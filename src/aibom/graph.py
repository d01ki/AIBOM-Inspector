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
from aibom.inventory import GRAPH_LOCKFILES, Inventory, dependencies_resolved
from aibom.models.entities import Package, RelationshipType
from aibom.models.findings import Finding, Severity
from aibom.policy import entity_in_production_scope, production_view


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


def build_dependency_list(inventory: Inventory, findings: list[Finding]) -> dict[str, Any]:
    """Every package in the inventory, with what is known about its relations.

    Unlike :func:`build_graph` nothing is filtered out: this is the complete
    dependency table (the same set CycloneDX lists as components). A package's
    ``relations`` is ``resolved`` only when a lockfile that records dependency
    edges covers it; otherwise its own dependencies are ``unknown`` — never
    presented as "none".
    """
    packages = [e for e in inventory.entities if isinstance(e, Package)]
    ids = {p.id for p in packages}
    depends: dict[str, list[str]] = {p.id: [] for p in packages}
    required_by: dict[str, list[str]] = {p.id: [] for p in packages}
    edge_evidence: dict[tuple[str, str], str] = {}
    for r in inventory.relationships:
        if r.relationship is not RelationshipType.DEPENDS_ON:
            continue
        if r.source_id in ids and r.target_id in ids and r.target_id not in depends[r.source_id]:
            depends[r.source_id].append(r.target_id)
            required_by[r.target_id].append(r.source_id)
            if r.source_evidence:
                edge_evidence[(r.source_id, r.target_id)] = r.source_evidence[0].location()
    worst: dict[str, Severity] = {}
    counts: dict[str, int] = {}
    for f in findings:
        if f.entity_id in ids:
            counts[f.entity_id] = counts.get(f.entity_id, 0) + 1
            current = worst.get(f.entity_id)
            if current is None or f.severity.rank > current.rank:
                worst[f.entity_id] = f.severity
    rows: list[dict[str, Any]] = []
    for p in sorted(packages, key=lambda p: (p.dependency_scope.value, p.name.lower())):
        files = sorted({ev.file for ev in p.source_evidence})
        rows.append({
            "id": p.id,
            "name": p.name,
            "ecosystem": p.ecosystem,
            "version": p.version,
            "version_pinned": p.version_pinned,
            "purl": p.purl,
            "scope": p.dependency_scope.value,
            "ai": p.ai,
            "sources": files,
            "locations": [ev.location() for ev in p.source_evidence[:4]],
            "from_lockfile": any(ev.kind == "lockfile" for ev in p.source_evidence),
            "relations": "resolved" if dependencies_resolved(p) else "unknown",
            "depends_on": depends[p.id],
            "required_by": required_by[p.id],
            "edge_evidence": {
                target: edge_evidence[(p.id, target)]
                for target in depends[p.id] if (p.id, target) in edge_evidence
            },
            "finding_count": counts.get(p.id, 0),
            "severity": worst[p.id].value if p.id in worst else None,
            "production": entity_in_production_scope(p),
            "source_contexts": sorted(c.value for c in p.source_contexts),
        })
    lockfiles = sorted({
        f for row in rows if row["from_lockfile"] for f in row["sources"]
        if f.replace("\\", "/").rsplit("/", 1)[-1].lower() in GRAPH_LOCKFILES
    })
    return {
        "packages": rows,
        "summary": {
            "total": len(rows),
            "direct": sum(1 for r in rows if r["scope"] == "direct"),
            "transitive": sum(1 for r in rows if r["scope"] == "transitive"),
            "ai": sum(1 for r in rows if r["ai"]),
            "relations_resolved": sum(1 for r in rows if r["relations"] == "resolved"),
            "edges": sum(len(r["depends_on"]) for r in rows),
            "graph_lockfiles": lockfiles,
        },
    }

