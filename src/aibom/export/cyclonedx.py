"""CycloneDX 1.6 (ML-BOM) exporter.

Renders an :class:`~aibom.inventory.Inventory` into a CycloneDX 1.6 document:

* ``Model``   → a ``machine-learning-model`` component (+ ``modelCard``)
* ``Dataset`` → a ``data`` component
* ``Prompt``  → a ``data`` component (``aibom:kind = prompt``)
* ``Agent``   → an ``application`` component
* ``Service`` → an entry in the top-level ``services`` array
* relationships → the ``dependencies`` graph

Every entity's ``bom-ref`` is its stable inventory id, so the dependency graph
and any downstream tooling can cross-reference components unambiguously.
Evidence and AIBOM-specific attributes are carried as ``aibom:*`` properties.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from aibom.inventory import Inventory
from aibom.models.entities import (
    Agent,
    Dataset,
    Entity,
    Model,
    Package,
    Prompt,
    Service,
)
from aibom.models.evidence import Evidence
from aibom.spdx import canonical_spdx, is_spdx

_SPEC_VERSION = "1.6"


def to_cyclonedx(inventory: Inventory) -> dict[str, Any]:
    """Build a CycloneDX 1.6 document (as a dict) from ``inventory``."""
    components: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []

    for entity in inventory.entities:
        if isinstance(entity, Service):
            services.append(_service(entity))
        else:
            components.append(_component(entity))

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": _serial_number(inventory),
        "version": 1,
        "metadata": _metadata(inventory),
        "components": components,
    }
    if services:
        doc["services"] = services
    dependencies = _dependencies(inventory)
    if dependencies:
        doc["dependencies"] = dependencies
    return doc


def to_cyclonedx_json(inventory: Inventory, *, indent: int | None = 2) -> str:
    """Serialize :func:`to_cyclonedx` to a JSON string."""
    return json.dumps(to_cyclonedx(inventory), indent=indent, ensure_ascii=False)


# ── metadata ─────────────────────────────────────────────────────────────────


def _serial_number(inventory: Inventory) -> str:
    # Deterministic urn:uuid derived from the target, so re-scans are stable.
    ns = uuid.NAMESPACE_URL
    return f"urn:uuid:{uuid.uuid5(ns, inventory.metadata.target)}"


def _metadata(inventory: Inventory) -> dict[str, Any]:
    meta = inventory.metadata
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": meta.tool,
                    "version": meta.tool_version,
                }
            ]
        },
        "properties": [
            _prop("aibom:target", meta.target),
            _prop("aibom:scan_created_at", meta.created_at),
        ],
    }


# ── components ───────────────────────────────────────────────────────────────


def _component(entity: Entity) -> dict[str, Any]:
    if isinstance(entity, Model):
        return _model_component(entity)
    if isinstance(entity, Dataset):
        return _dataset_component(entity)
    if isinstance(entity, Prompt):
        return _prompt_component(entity)
    if isinstance(entity, Agent):
        return _agent_component(entity)
    if isinstance(entity, Package):
        return _package_component(entity)
    # Fallback for any future entity type: a generic component.
    return _base_component("library", entity)


def _base_component(ctype: str, entity: Entity) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": ctype,
        "bom-ref": entity.id,
        "name": entity.name,
    }
    props = _evidence_props(entity.source_evidence)
    if props:
        comp["properties"] = props
    return comp


def _model_component(model: Model) -> dict[str, Any]:
    comp = _base_component("machine-learning-model", model)
    if model.author:
        comp["supplier"] = {"name": model.author}
    licenses = _licenses(model.license)
    if licenses:
        comp["licenses"] = licenses
    card = _model_card(model)
    if card:
        comp["modelCard"] = card

    props: list[dict[str, str]] = comp.setdefault("properties", [])
    _append_prop(props, "aibom:provider", model.provider)
    _append_prop(props, "aibom:revision", model.revision)
    props.append(_prop("aibom:revision_pinned", _b(model.revision_pinned)))
    _append_prop(props, "aibom:formats", ",".join(model.formats) or None)
    _append_prop(props, "aibom:downloads", _n(model.downloads))
    _append_prop(props, "aibom:gated", _b(model.gated) if model.gated is not None else None)
    _append_prop(props, "aibom:last_modified", model.last_modified)
    _append_prop(
        props, "aibom:has_model_card",
        _b(model.has_model_card) if model.has_model_card is not None else None,
    )
    props.append(_prop("aibom:resolved", _b(model.resolved)))
    _dedupe_or_drop_props(comp)
    return comp


def _dataset_component(dataset: Dataset) -> dict[str, Any]:
    comp = _base_component("data", dataset)
    if dataset.author:
        comp["supplier"] = {"name": dataset.author}
    licenses = _licenses(dataset.license)
    if licenses:
        comp["licenses"] = licenses

    props: list[dict[str, str]] = comp.setdefault("properties", [])
    _append_prop(props, "aibom:source", dataset.source)
    _append_prop(props, "aibom:provenance", dataset.provenance)
    _append_prop(props, "aibom:downloads", _n(dataset.downloads))
    _append_prop(props, "aibom:last_modified", dataset.last_modified)
    props.append(_prop("aibom:resolved", _b(dataset.resolved)))
    _dedupe_or_drop_props(comp)
    return comp


def _prompt_component(prompt: Prompt) -> dict[str, Any]:
    comp = _base_component("data", prompt)
    props: list[dict[str, str]] = comp.setdefault("properties", [])
    props.append(_prop("aibom:kind", "prompt"))
    _append_prop(props, "aibom:prompt_kind", prompt.kind)
    _append_prop(props, "aibom:content_hash", prompt.content_hash)
    _dedupe_or_drop_props(comp)
    return comp


def _agent_component(agent: Agent) -> dict[str, Any]:
    comp = _base_component("application", agent)
    props: list[dict[str, str]] = comp.setdefault("properties", [])
    props.append(_prop("aibom:kind", "agent"))
    _append_prop(props, "aibom:framework", agent.framework)
    if agent.tools:
        _append_prop(props, "aibom:tools", ",".join(agent.tools))
    _dedupe_or_drop_props(comp)
    return comp


def _package_component(pkg: Package) -> dict[str, Any]:
    comp = _base_component("library", pkg)
    if pkg.version:
        comp["version"] = pkg.version
    if pkg.purl:
        comp["purl"] = pkg.purl
    props: list[dict[str, str]] = comp.setdefault("properties", [])
    _append_prop(props, "aibom:ecosystem", pkg.ecosystem)
    props.append(_prop("aibom:version_pinned", _b(pkg.version_pinned)))
    props.append(_prop("aibom:ai", _b(pkg.ai)))
    _dedupe_or_drop_props(comp)
    return comp


def _model_card(model: Model) -> dict[str, Any] | None:
    considerations: dict[str, Any] = {}
    if model.gated:
        considerations["useCases"] = ["gated: access requires acceptance of terms"]
    card: dict[str, Any] = {}
    if considerations:
        card["considerations"] = considerations
    # A modelCard with only properties is still useful context for consumers.
    if model.provider:
        card.setdefault("properties", []).append(_prop("aibom:provider", model.provider))
    return card or None


# ── services ─────────────────────────────────────────────────────────────────


def _service(service: Service) -> dict[str, Any]:
    svc: dict[str, Any] = {"bom-ref": service.id, "name": service.name}
    if service.endpoint:
        svc["endpoints"] = [service.endpoint]
    props = _evidence_props(service.source_evidence)
    props.append(_prop("aibom:service_kind", service.kind))
    svc["properties"] = props
    return svc


# ── dependencies ─────────────────────────────────────────────────────────────


def _dependencies(inventory: Inventory) -> list[dict[str, Any]]:
    depends: dict[str, list[str]] = {}
    known = {e.id for e in inventory.entities}
    for rel in inventory.relationships:
        if rel.source_id not in known or rel.target_id not in known:
            continue
        targets = depends.setdefault(rel.source_id, [])
        if rel.target_id not in targets:
            targets.append(rel.target_id)
    return [{"ref": ref, "dependsOn": t} for ref, t in depends.items() if t]


# ── licenses ─────────────────────────────────────────────────────────────────


def _licenses(license_str: str | None) -> list[dict[str, Any]] | None:
    if not license_str:
        return None
    normalized = license_str.strip()
    if is_spdx(normalized):
        return [{"license": {"id": canonical_spdx(normalized)}}]
    return [{"license": {"name": normalized}}]


# ── property / evidence helpers ──────────────────────────────────────────────


def _evidence_props(evidence: list[Evidence]) -> list[dict[str, str]]:
    props: list[dict[str, str]] = []
    for ev in evidence:
        props.append(_prop("aibom:evidence", f"{ev.location()} [{ev.matched_pattern}]"))
        props.append(_prop("aibom:evidence_confidence", f"{ev.confidence:.2f}"))
    return props


def _prop(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}


def _append_prop(props: list[dict[str, str]], name: str, value: str | None) -> None:
    if value is not None and value != "":
        props.append(_prop(name, value))


def _dedupe_or_drop_props(comp: dict[str, Any]) -> None:
    props = comp.get("properties")
    if not props:
        comp.pop("properties", None)


def _b(value: bool | None) -> str:
    return "true" if value else "false"


def _n(value: int | None) -> str | None:
    return None if value is None else str(value)
