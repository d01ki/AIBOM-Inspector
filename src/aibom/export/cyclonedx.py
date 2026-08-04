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

The document targets the **CISA 2026 SBOM minimum elements**, which apply to AI
software as much as to conventional software: it carries an SBOM author, a
generation context (lifecycle phase), a primary component, per-component
producers, identifiers, licenses and artifact digests, and an explicit
dependency entry for every component — including leaves.

What static analysis genuinely cannot know is **declared** rather than left
blank: each gap becomes a ``cisa:known-unknown`` property naming the field and
the reason, which is what the 2026 baseline asks for ("distinguish data you
lack from data you withhold"). :mod:`aibom.compliance.minimum_elements` scores
the result.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
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

#: Lifecycle phases CycloneDX 1.6 defines for ``metadata.lifecycles``.
LIFECYCLE_PHASES = (
    "design",
    "pre-build",
    "build",
    "post-build",
    "operations",
    "discovery",
    "decommission",
)

#: Static source analysis produces a pre-build view: it sees what the source and
#: the lockfiles declare, never what a build step injects.
DEFAULT_LIFECYCLE = "pre-build"

_PRIMARY_REF = "aibom:primary-component"

# CycloneDX only accepts digests of these hex lengths.
_RE_DIGEST = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})$")

# Hugging Face repo ids look like "org/name".
_RE_HF_REPO_ID = re.compile(r"^[A-Za-z0-9][\w\-.]*/[\w\-.]+$")


@dataclass(frozen=True)
class SbomContext:
    """Authorship and generation context the scanner cannot infer from source.

    These are 2026 minimum elements about the *document*, not about the scanned
    code, so they come from whoever runs the scan (CLI flags or ``aibom.toml``).
    """

    author: str | None = None
    author_email: str | None = None
    supplier: str | None = None
    lifecycle: str = DEFAULT_LIFECYCLE
    document_version: int = 1

    def normalized_lifecycle(self) -> str:
        return self.lifecycle if self.lifecycle in LIFECYCLE_PHASES else DEFAULT_LIFECYCLE


def to_cyclonedx(inventory: Inventory, *, context: SbomContext | None = None) -> dict[str, Any]:
    """Build a CycloneDX 1.6 document (as a dict) from ``inventory``."""
    ctx = context or SbomContext()
    components: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []

    for entity in inventory.entities:
        if isinstance(entity, Service):
            services.append(_service(entity, ctx))
        else:
            components.append(_component(entity, ctx))

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": _serial_number(inventory),
        "version": max(ctx.document_version, 1),
        "metadata": _metadata(inventory, ctx),
        "components": components,
        # Every component gets an entry, even a leaf: "no dependencies" is a
        # statement the 2026 baseline expects to be made, not inferred.
        "dependencies": _dependencies(inventory),
    }
    if services:
        doc["services"] = services
    return doc


def to_cyclonedx_json(
    inventory: Inventory, *, indent: int | None = 2, context: SbomContext | None = None
) -> str:
    """Serialize :func:`to_cyclonedx` to a JSON string."""
    return json.dumps(
        to_cyclonedx(inventory, context=context), indent=indent, ensure_ascii=False
    )


# ── metadata ─────────────────────────────────────────────────────────────────


def _serial_number(inventory: Inventory) -> str:
    # Deterministic urn:uuid derived from the target, so re-scans are stable.
    ns = uuid.NAMESPACE_URL
    return f"urn:uuid:{uuid.uuid5(ns, inventory.metadata.target)}"


def _metadata(inventory: Inventory, ctx: SbomContext) -> dict[str, Any]:
    meta = inventory.metadata
    coverage, coverage_note = _coverage(inventory)
    properties = [
        _prop("aibom:target", meta.target),
        _prop("aibom:scan_created_at", meta.created_at),
        _prop("cisa:coverage", coverage),
        _prop("cisa:coverage-note", coverage_note),
        _prop(
            "cisa:generation-context-note",
            "Generated by static analysis of source and dependency manifests; "
            "no build was run and no scanned code was executed."
            if ctx.normalized_lifecycle() == DEFAULT_LIFECYCLE
            else f"Lifecycle phase '{ctx.normalized_lifecycle()}' declared by the operator.",
        ),
    ]

    doc_meta: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # A pre-defined phase carries no description of its own in CycloneDX, so
        # the how-it-was-generated note rides along as a property.
        "lifecycles": [{"phase": ctx.normalized_lifecycle()}],
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": meta.tool,
                    "version": meta.tool_version,
                }
            ]
        },
        "component": _primary_component(inventory, ctx),
    }
    if ctx.author:
        author: dict[str, str] = {"name": ctx.author}
        if ctx.author_email:
            author["email"] = ctx.author_email
        doc_meta["authors"] = [author]
        doc_meta["manufacturer"] = {"name": ctx.author}
    else:
        properties.append(
            _unknown(
                "sbom-author",
                "not supplied to the generator; pass --sbom-author or set it in aibom.toml",
            )
        )
    if ctx.supplier:
        doc_meta["supplier"] = {"name": ctx.supplier}
    properties.append(
        _unknown(
            "sbom-author-signature",
            "AIBOM Inspector emits an unsigned document; sign it out of band "
            "(cosign, cyclonedx-cli sign) before distribution",
        )
    )
    doc_meta["properties"] = properties
    return doc_meta


def _primary_component(inventory: Inventory, ctx: SbomContext) -> dict[str, Any]:
    """The software this SBOM is about — the anchor for the coverage element."""
    target = inventory.metadata.target
    comp: dict[str, Any] = {
        "type": "application",
        "bom-ref": _PRIMARY_REF,
        "name": _primary_name(target),
    }
    purl = _repo_purl(target)
    if purl:
        comp["purl"] = purl
    if ctx.supplier or ctx.author:
        comp["supplier"] = {"name": ctx.supplier or ctx.author}
    properties = [_prop("aibom:target", target)]
    if "version" not in comp:
        properties.append(
            _unknown(
                "component-version",
                "the scanned working tree is not a released artifact; "
                "no version was supplied",
            )
        )
    if not purl:
        properties.append(
            _unknown("component-identifier", "scan target is a local path, not a repository URL")
        )
    if not comp.get("supplier"):
        properties.append(
            _unknown("component-producer", "no SBOM supplier configured (--sbom-supplier)")
        )
    properties.extend(
        [
            _unknown(
                "component-hash",
                "a working tree has no distributable artifact to digest; "
                "generate a post-build SBOM to record one",
            ),
            _unknown("component-hash-algorithm", "no artifact digest for the primary component"),
            _unknown("component-license", "not declared to the generator"),
        ]
    )
    comp["properties"] = properties
    return comp


def _primary_name(target: str) -> str:
    """A human name for the scan target: 'owner/repo' for a URL, else the dir."""
    cleaned = target.rstrip("/")
    if cleaned.lower().startswith(("http://", "https://")):
        parts = [p for p in cleaned.split("://", 1)[1].split("/") if p]
        if len(parts) >= 3:
            return "/".join(parts[-2:]).removesuffix(".git")
        return cleaned
    return cleaned.rsplit("/", 1)[-1] or cleaned


def _repo_purl(target: str) -> str | None:
    """``pkg:github/owner/repo`` for a GitHub URL target — a real identifier."""
    cleaned = target.rstrip("/").removesuffix(".git")
    if not cleaned.lower().startswith(("http://", "https://")):
        return None
    host, _, path = cleaned.split("://", 1)[1].partition("/")
    parts = [p for p in path.split("/") if p]
    if host.lower() in {"github.com", "www.github.com"} and len(parts) >= 2:
        return f"pkg:github/{parts[0]}/{parts[1]}"
    return None


def _coverage(inventory: Inventory) -> tuple[str, str]:
    """Report what the scan could actually reach — the 2026 'coverage' element."""
    packages = [e for e in inventory.entities if isinstance(e, Package)]
    if not packages:
        return (
            "transitive",
            "no software dependencies were declared; every discovered component is included",
        )
    from_lockfile = any(
        ev.kind == "lockfile" for pkg in packages for ev in pkg.source_evidence
    )
    if from_lockfile:
        return (
            "transitive",
            "dependencies resolved from lockfiles, so transitive components are included",
        )
    return (
        "declared-dependencies-only",
        "no lockfile was found; only dependencies declared in manifests are listed, "
        "so transitive components are missing",
    )


# ── components ───────────────────────────────────────────────────────────────


def _component(entity: Entity, ctx: SbomContext) -> dict[str, Any]:
    if isinstance(entity, Model):
        comp = _model_component(entity)
    elif isinstance(entity, Dataset):
        comp = _dataset_component(entity)
    elif isinstance(entity, Prompt):
        comp = _prompt_component(entity, ctx)
    elif isinstance(entity, Agent):
        comp = _agent_component(entity, ctx)
    elif isinstance(entity, Package):
        comp = _package_component(entity)
    else:
        # Fallback for any future entity type: a generic component.
        comp = _base_component("library", entity)
    _declare_unknowns(comp, entity)
    return comp


def _base_component(ctype: str, entity: Entity) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": ctype,
        "bom-ref": entity.id,
        "name": entity.name,
    }
    props = _evidence_props(entity.source_evidence)
    props.extend(_analysis_props(entity))
    if props:
        comp["properties"] = props
    return comp


def _model_component(model: Model) -> dict[str, Any]:
    comp = _base_component("machine-learning-model", model)
    if model.revision:
        comp["version"] = model.revision
    purl = _hf_purl(model.name, model.provider, model.revision)
    if purl:
        comp["purl"] = purl
        comp["externalReferences"] = [
            {"type": "distribution", "url": f"https://huggingface.co/{model.name}"}
        ]
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
        props,
        "aibom:has_model_card",
        _b(model.has_model_card) if model.has_model_card is not None else None,
    )
    props.append(_prop("aibom:resolved", _b(model.resolved)))
    _dedupe_or_drop_props(comp)
    return comp


def _dataset_component(dataset: Dataset) -> dict[str, Any]:
    comp = _base_component("data", dataset)
    purl = _hf_purl(dataset.name, dataset.source, None)
    if purl:
        # purl has no dataset type; the qualifier keeps the coordinates honest.
        comp["purl"] = f"{purl}?repository_type=dataset"
        comp["externalReferences"] = [
            {"type": "distribution", "url": f"https://huggingface.co/datasets/{dataset.name}"}
        ]
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


def _prompt_component(prompt: Prompt, ctx: SbomContext) -> dict[str, Any]:
    comp = _base_component("data", prompt)
    # A prompt is a first-party component: its content digest *is* its hash, and
    # its producer is whoever ships the software.
    digest = _hashes("SHA-256", prompt.content_hash)
    if digest:
        comp["hashes"] = digest
    _apply_first_party_supplier(comp, ctx)
    props: list[dict[str, str]] = comp.setdefault("properties", [])
    props.append(_prop("aibom:kind", "prompt"))
    _append_prop(props, "aibom:prompt_kind", prompt.kind)
    _append_prop(props, "aibom:content_hash", prompt.content_hash)
    _append_prop(props, "aibom:prompt_source_kind", prompt.source_kind)
    _append_prop(props, "aibom:prompt_sink_kind", prompt.sink_kind)
    _append_prop(props, "aibom:prompt_trust_boundary", prompt.trust_boundary)
    if prompt.user_controlled is not None:
        props.append(_prop("aibom:prompt_user_controlled", _b(prompt.user_controlled)))
    if prompt.model_refs:
        _append_prop(props, "aibom:prompt_model_refs", ",".join(prompt.model_refs))
    if prompt.tool_refs:
        _append_prop(props, "aibom:prompt_tool_refs", ",".join(prompt.tool_refs))
    for capability in prompt.capabilities:
        props.append(
            _prop(
                "aibom:prompt_bound_capability",
                (
                    f"{capability.tool_name}:{capability.kind}:"
                    f"{capability.operation}:{capability.severity}:"
                    f"params={','.join(capability.controlled_parameters)}"
                ),
            )
        )
    for step in prompt.data_flow_path:
        location = f"{step.file}:{step.line}" if step.line is not None else step.file
        symbol = f" {step.symbol}" if step.symbol else ""
        props.append(_prop("aibom:prompt_flow_step", f"{location} [{step.operation}]{symbol}"))
    _dedupe_or_drop_props(comp)
    return comp


def _agent_component(agent: Agent, ctx: SbomContext) -> dict[str, Any]:
    comp = _base_component("application", agent)
    _apply_first_party_supplier(comp, ctx)
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
    if pkg.producer:
        supplier: dict[str, Any] = {"name": pkg.producer}
        if pkg.producer_url:
            supplier["url"] = [pkg.producer_url]
        comp["supplier"] = supplier
    licenses = _licenses(pkg.license)
    if licenses:
        comp["licenses"] = licenses
    hashes = _hashes(pkg.hash_algorithm, pkg.content_hash)
    if hashes:
        comp["hashes"] = hashes
    props: list[dict[str, str]] = comp.setdefault("properties", [])
    _append_prop(props, "aibom:ecosystem", pkg.ecosystem)
    props.append(_prop("aibom:version_pinned", _b(pkg.version_pinned)))
    props.append(_prop("aibom:ai", _b(pkg.ai)))
    props.append(_prop("aibom:dependency_scope", pkg.dependency_scope.value))
    _append_prop(props, "aibom:hash_artifact", pkg.hash_artifact)
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


def _service(service: Service, ctx: SbomContext) -> dict[str, Any]:
    svc: dict[str, Any] = {"bom-ref": service.id, "name": service.name}
    if service.endpoint:
        svc["endpoints"] = [service.endpoint]
    props = _evidence_props(service.source_evidence)
    props.extend(_analysis_props(service))
    props.append(_prop("aibom:service_kind", service.kind))
    svc["properties"] = props
    _declare_unknowns(svc, service)
    return svc


# ── dependencies ─────────────────────────────────────────────────────────────


def _dependencies(inventory: Inventory) -> list[dict[str, Any]]:
    """Every component gets an entry — a leaf's empty ``dependsOn`` is a claim.

    The primary component is the root: everything nothing else depends on hangs
    off it, so the graph spans the whole inventory instead of leaving components
    unreachable from the software the SBOM describes.
    """
    known = [e.id for e in inventory.entities]
    known_set = set(known)
    depends: dict[str, list[str]] = {ref: [] for ref in known}
    for rel in inventory.relationships:
        if rel.source_id not in known_set or rel.target_id not in known_set:
            continue
        targets = depends[rel.source_id]
        if rel.target_id not in targets:
            targets.append(rel.target_id)

    depended_on = {target for targets in depends.values() for target in targets}
    roots = [ref for ref in known if ref not in depended_on]
    entries = [{"ref": _PRIMARY_REF, "dependsOn": roots}]
    entries.extend({"ref": ref, "dependsOn": depends[ref]} for ref in known)
    return entries


# ── known unknowns (CISA 2026) ───────────────────────────────────────────────

# Why a field is unknown, per entity kind. Static analysis has honest limits;
# the baseline asks that they be stated, not hidden behind an empty field.
_UNKNOWN_REASONS: dict[str, dict[str, str]] = {
    "component-version": {
        "model": "the model reference in source is not pinned to a revision",
        "dataset": "the dataset reference in source is not pinned to a revision",
        "package": "the manifest declares a range and no lockfile pins it",
        "*": "first-party component found in source; it has no released version",
    },
    "component-producer": {
        "model": "hub metadata was not resolved; re-run with --resolve",
        "dataset": "hub metadata was not resolved; re-run with --resolve",
        "package": "no lockfile recorded the registry that supplied the artifact",
        "*": "no SBOM supplier configured (--sbom-supplier)",
    },
    "component-identifier": {
        "model": "not a Hugging Face repo id, so no package coordinates exist",
        "dataset": "not a Hugging Face repo id, so no package coordinates exist",
        "package": "no purl type is defined for this ecosystem",
        "*": "first-party component found in source; no ecosystem coordinates exist",
    },
    "component-hash": {
        "model": "static analysis never downloads weights, so no artifact digest exists",
        "dataset": "static analysis never downloads data files, so no artifact digest exists",
        "package": "no lockfile digest was found for this package",
        "*": "component is source-derived and has no distributable artifact",
    },
    "component-hash-algorithm": {
        "*": "no artifact digest was collected for this component",
    },
    "component-license": {
        "model": "no license on the model card, or hub metadata was not resolved",
        "dataset": "no license on the dataset card, or hub metadata was not resolved",
        "package": "registry metadata is not collected by static manifest analysis",
        "*": "no license declared for this first-party component",
    },
}

# Component-scope fields, and how to see whether the component carries one.
_COMPONENT_FIELD_CHECKS: tuple[tuple[str, str], ...] = (
    ("component-version", "version"),
    ("component-producer", "supplier"),
    ("component-identifier", "purl"),
    ("component-hash", "hashes"),
    ("component-hash-algorithm", "hashes"),
    ("component-license", "licenses"),
)


def _declare_unknowns(comp: dict[str, Any], entity: Entity) -> None:
    """Declare every minimum element this component could not supply."""
    kind = entity.type.value
    props: list[dict[str, str]] = comp.setdefault("properties", [])
    for field_id, key in _COMPONENT_FIELD_CHECKS:
        if comp.get(key):
            continue
        reasons = _UNKNOWN_REASONS[field_id]
        props.append(_unknown(field_id, reasons.get(kind, reasons["*"])))


def _unknown(field_id: str, reason: str) -> dict[str, str]:
    """A ``cisa:known-unknown`` property: which field, and why it is empty."""
    return _prop("cisa:known-unknown", f"{field_id}: {reason}")


# ── identifiers, digests, suppliers ──────────────────────────────────────────


def _hf_purl(name: str, provider: str | None, revision: str | None) -> str | None:
    """``pkg:huggingface/org/name@revision`` for a hub-hosted component."""
    if (provider or "").lower() != "huggingface" or not _RE_HF_REPO_ID.match(name):
        return None
    base = f"pkg:huggingface/{name}"
    return f"{base}@{revision}" if revision else base


def _hashes(algorithm: str | None, content: str | None) -> list[dict[str, str]] | None:
    """One CycloneDX hash entry, or nothing if the digest is not verifiable."""
    if not algorithm or not content:
        return None
    digest = content.strip().lower()
    if not _RE_DIGEST.match(digest):
        return None
    return [{"alg": algorithm, "content": digest}]


def _apply_first_party_supplier(comp: dict[str, Any], ctx: SbomContext) -> None:
    """A prompt or agent is produced by whoever ships the scanned software."""
    producer = ctx.supplier or ctx.author
    if producer:
        comp["supplier"] = {"name": producer}


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


def _analysis_props(entity: Entity) -> list[dict[str, str]]:
    props: list[dict[str, str]] = []
    if entity.detector_ids:
        props.append(_prop("aibom:detectors", ",".join(sorted(entity.detector_ids))))
    usage = entity.usage
    for name in ("declared", "imported", "instantiated", "invoked", "runtime_observed"):
        props.append(_prop(f"aibom:usage:{name}", _b(getattr(usage, name))))
    props.append(_prop("aibom:usage:reachable", usage.reachable.value))
    if entity.source_contexts:
        props.append(
            _prop(
                "aibom:source_contexts",
                ",".join(sorted(context.value for context in entity.source_contexts)),
            )
        )
    props.append(_prop("aibom:value_resolution", entity.value_resolution.value))
    for step in entity.resolution_path:
        location = f"{step.file}:{step.line}" if step.line is not None else step.file
        symbol = f" {step.symbol}" if step.symbol else ""
        props.append(_prop("aibom:resolution_step", f"{location} [{step.operation}]{symbol}"))
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
