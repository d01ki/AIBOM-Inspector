"""CISA 2026 *Minimum Elements for an SBOM* conformance checking.

The 2026 baseline (CISA, NSA, FBI and international partners, 29 July 2026)
replaces the 2021 NTIA minimum elements. It expands the required data fields,
turns *depth* into *coverage* (transitive dependencies included), requires the
author to say explicitly what is unknown or withheld, and states that the
baseline applies to all software — open source, **AI systems**, and SaaS.

This module scores a CycloneDX document against that baseline, field by field,
and reports each field as satisfied, partially satisfied, explicitly declared
unknown, or missing. It reads a document, not an inventory, so it works on any
CycloneDX SBOM — the one AIBOM Inspector just produced, or someone else's.

**Declared unknowns are a pass, not a failure.** The baseline asks authors to
distinguish data they do not have from data they are withholding, so a field
that cannot be known from static analysis (an artifact digest for a model whose
weights were never downloaded) conforms when it is declared. Declarations are
carried as ``cisa:known-unknown`` properties with the value
``"<field-id>: <reason>"`` — see :mod:`aibom.export.cyclonedx`.

.. note::
   The field names and grouping below follow the 2026 publication as reported
   publicly; verify them against the authoritative PDF (see
   :data:`CISA_2026_REFERENCE`) before quoting this table in an audit. Each
   entry is a single :class:`ElementSpec`, so a correction is a one-line edit.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

CISA_2026_REFERENCE = (
    "https://www.cisa.gov/resources-tools/resources/"
    "2026-minimum-elements-software-bill-materials-sbom"
)
STANDARD_NAME = "CISA 2026 Minimum Elements for a Software Bill of Materials (SBOM)"

#: Property name carrying an explicit "known unknown" declaration.
KNOWN_UNKNOWN_PROPERTY = "cisa:known-unknown"

#: Data formats the 2026 baseline names as machine-readable SBOM formats.
#: SWID tags were dropped from the 2021 list.
ACCEPTED_FORMATS = ("CycloneDX", "SPDX")


class ElementScope(str, Enum):
    """Whether an element describes the SBOM document or each component in it."""

    DOCUMENT = "document"
    COMPONENT = "component"


class ElementStatus(str, Enum):
    """Outcome for one minimum element."""

    SATISFIED = "satisfied"
    PARTIAL = "partial"
    DECLARED_UNKNOWN = "declared_unknown"
    MISSING = "missing"


class ElementOrigin(str, Enum):
    """How the element relates to the 2021 NTIA baseline it replaces."""

    CARRIED_OVER = "carried_over"
    UPDATED_2026 = "updated_2026"
    NEW_2026 = "new_2026"


@dataclass(frozen=True)
class ElementSpec:
    """One minimum element and how to detect it in a CycloneDX document."""

    id: str
    name: str
    scope: ElementScope
    origin: ElementOrigin
    cyclonedx_path: str
    description: str
    remediation: str
    present: Callable[[dict[str, Any]], bool]


class ElementResult(BaseModel):
    """Per-element outcome, with the counts that produced it."""

    id: str
    name: str
    scope: ElementScope
    origin: ElementOrigin
    status: ElementStatus
    cyclonedx_path: str
    description: str
    applicable: int = Field(description="Objects the element applies to (1 for document scope).")
    present: int = Field(description="Objects that carry the data.")
    declared_unknown: int = Field(description="Objects that explicitly declare it unknown.")
    undeclared_gaps: list[str] = Field(
        default_factory=list, description="Up to 10 component names missing the data silently."
    )
    remediation: str

    @property
    def conformant(self) -> bool:
        """True when the element is satisfied, or every gap is declared."""
        return self.status is not ElementStatus.MISSING


class MinimumElementsReport(BaseModel):
    """Conformance of one SBOM document against the 2026 minimum elements."""

    standard: str = STANDARD_NAME
    reference: str = CISA_2026_REFERENCE
    document_format: str = Field(description="Format and version detected in the document.")
    components: int
    transitive_components: int
    elements: list[ElementResult]

    @property
    def conformant(self) -> bool:
        """True when no element is silently missing."""
        return all(e.conformant for e in self.elements)

    @property
    def satisfied(self) -> int:
        return sum(1 for e in self.elements if e.status is ElementStatus.SATISFIED)

    @property
    def missing(self) -> int:
        return sum(1 for e in self.elements if e.status is ElementStatus.MISSING)

    @property
    def declared_unknown(self) -> int:
        return sum(1 for e in self.elements if e.status is ElementStatus.DECLARED_UNKNOWN)

    @property
    def partial(self) -> int:
        return sum(1 for e in self.elements if e.status is ElementStatus.PARTIAL)

    def to_dict(self) -> dict[str, Any]:
        """Serialize including the computed summary (for JSON output and the API)."""
        return self.model_dump() | {
            "conformant": self.conformant,
            "summary": {
                "total": len(self.elements),
                "satisfied": self.satisfied,
                "partial": self.partial,
                "declared_unknown": self.declared_unknown,
                "missing": self.missing,
            },
        }


class UnsupportedDocument(ValueError):
    """Raised when the document is not a CycloneDX SBOM this checker can read."""


# ── element table ────────────────────────────────────────────────────────────


def _nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return value is not None


def _named(value: Any) -> bool:
    """True for an organizational entity (or list of them) that carries a name."""
    items = value if isinstance(value, list) else [value]
    return any(isinstance(i, dict) and _nonempty(i.get("name")) for i in items)


def _doc_author(doc: dict[str, Any]) -> bool:
    meta = _metadata(doc)
    return (
        _named(meta.get("authors"))
        or _named(meta.get("author"))
        or _named(meta.get("manufacturer"))
        or _named(meta.get("supplier"))
    )


def _doc_tool(doc: dict[str, Any]) -> bool:
    tools = _metadata(doc).get("tools")
    if isinstance(tools, dict):
        return any(
            _nonempty(t.get("name"))
            for t in tools.get("components", [])
            if isinstance(t, dict)
        )
    if isinstance(tools, list):  # CycloneDX <= 1.4 shape
        return any(isinstance(t, dict) and _nonempty(t.get("name")) for t in tools)
    return False


def _doc_lifecycles(doc: dict[str, Any]) -> bool:
    lifecycles = _metadata(doc).get("lifecycles")
    return isinstance(lifecycles, list) and any(
        isinstance(item, dict) and _nonempty(item.get("phase") or item.get("name"))
        for item in lifecycles
    )


def _component_hash_field(key: str) -> Callable[[dict[str, Any]], bool]:
    def present(component: dict[str, Any]) -> bool:
        hashes = component.get("hashes")
        return isinstance(hashes, list) and any(
            isinstance(h, dict) and _nonempty(h.get(key)) for h in hashes
        )

    return present


def _component_producer(component: dict[str, Any]) -> bool:
    # `provider` is the services equivalent of a component's supplier.
    return (
        _named(component.get("supplier"))
        or _named(component.get("manufacturer"))
        or _named(component.get("provider"))
        or _nonempty(component.get("publisher"))
        or _named(component.get("authors"))
    )


def _component_identifier(component: dict[str, Any]) -> bool:
    # bom-ref is deliberately excluded: it identifies a row in this document,
    # not the software in the wider ecosystem.
    return any(
        _nonempty(component.get(key))
        for key in ("purl", "cpe", "swid", "omniborId", "swhid")
    )


def _component_license(component: dict[str, Any]) -> bool:
    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return False
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        if _nonempty(entry.get("expression")):
            return True
        lic = entry.get("license")
        if isinstance(lic, dict) and (_nonempty(lic.get("id")) or _nonempty(lic.get("name"))):
            return True
    return False


_DOCUMENT_ELEMENTS: tuple[ElementSpec, ...] = (
    ElementSpec(
        id="sbom-author",
        name="SBOM Author",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="metadata.authors[] / metadata.manufacturer",
        description="The entity that created the SBOM data (renamed from 'Author of SBOM Data').",
        remediation="Record the authoring organization, e.g. `aibom scan --sbom-author 'Acme'`.",
        present=_doc_author,
    ),
    ElementSpec(
        id="sbom-author-signature",
        name="SBOM Author Signature",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="signature",
        description="A digital signature that lets a consumer confirm the SBOM is unaltered.",
        remediation=(
            "Sign the emitted document out of band (cosign, cyclonedx-cli sign) and "
            "distribute the signature with it."
        ),
        present=lambda doc: _nonempty(doc.get("signature")),
    ),
    ElementSpec(
        id="sbom-timestamp",
        name="SBOM Timestamp",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.CARRIED_OVER,
        cyclonedx_path="metadata.timestamp",
        description="Date and time the SBOM data was last updated.",
        remediation="Emit metadata.timestamp when generating the document.",
        present=lambda doc: _nonempty(_metadata(doc).get("timestamp")),
    ),
    ElementSpec(
        id="sbom-version",
        name="SBOM Version",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="version (+ serialNumber)",
        description="Iteration of this SBOM, so consumers can tell a revision from a reissue.",
        remediation="Increment the document version when re-issuing an SBOM for the same build.",
        present=lambda doc: isinstance(doc.get("version"), int) and doc["version"] >= 1,
    ),
    ElementSpec(
        id="sbom-data-format-name",
        name="SBOM Data Format (name)",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="bomFormat",
        description="Machine-readable format of the SBOM data (SPDX or CycloneDX).",
        remediation="Emit the format name in the document envelope.",
        present=lambda doc: str(doc.get("bomFormat", "")) in ACCEPTED_FORMATS,
    ),
    ElementSpec(
        id="sbom-data-format-version",
        name="SBOM Data Format (version)",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="specVersion",
        description="Version of that format, so tools know how to read the document.",
        remediation="Emit the specification version in the document envelope.",
        present=lambda doc: _nonempty(doc.get("specVersion")),
    ),
    ElementSpec(
        id="sbom-tool-name",
        name="SBOM Tool Name",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="metadata.tools.components[].name",
        description="Tool that generated the SBOM — context for judging data fidelity.",
        remediation="Record the generating tool and its version in the document metadata.",
        present=_doc_tool,
    ),
    ElementSpec(
        id="sbom-generation-context",
        name="SBOM Generation Context",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="metadata.lifecycles[].phase",
        description=(
            "Lifecycle phase the SBOM was produced in. A pre-build SBOM and a "
            "post-build SBOM describe different component sets."
        ),
        remediation="Declare the lifecycle phase, e.g. `--sbom-lifecycle post-build`.",
        present=_doc_lifecycles,
    ),
)

_COMPONENT_ELEMENTS: tuple[ElementSpec, ...] = (
    ElementSpec(
        id="component-name",
        name="Component Name",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.CARRIED_OVER,
        cyclonedx_path="components[].name",
        description="Name assigned to the component by its producer.",
        remediation="Every component must carry a name.",
        present=lambda c: _nonempty(c.get("name")),
    ),
    ElementSpec(
        id="component-version",
        name="Component Version",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="components[].version",
        description="Identifier of the specific release (renamed from 'Version of the Component').",
        remediation=(
            "Resolve versions from a lockfile, or pin the model revision, so the "
            "component identifies one release rather than a range."
        ),
        present=lambda c: _nonempty(c.get("version")),
    ),
    ElementSpec(
        id="component-producer",
        name="Component Producer",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="components[].supplier / publisher",
        description=(
            "Entity that produced or supplied the component "
            "(renamed from 'Supplier Name')."
        ),
        remediation="Record the supplying registry, model-hub author, or first-party owner.",
        present=_component_producer,
    ),
    ElementSpec(
        id="component-identifier",
        name="Software Identifier",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="components[].purl / cpe",
        description="At least one ecosystem-wide identifier usable as a database lookup key.",
        remediation="Emit a purl (or CPE) for every component that has ecosystem coordinates.",
        present=_component_identifier,
    ),
    ElementSpec(
        id="component-hash",
        name="Component Hash",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="components[].hashes[].content",
        description=(
            "Cryptographic digest of the component — mandatory in 2026, where the "
            "2021 elements only recommended it."
        ),
        remediation=(
            "Take digests from lockfiles (package-lock.json, poetry.lock, uv.lock, "
            "Cargo.lock, composer.lock) or hash the artifact at build time."
        ),
        present=_component_hash_field("content"),
    ),
    ElementSpec(
        id="component-hash-algorithm",
        name="Component Hash Algorithm",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="components[].hashes[].alg",
        description="Algorithm behind the digest, so a consumer can recompute and compare it.",
        remediation="Always emit the algorithm alongside the digest.",
        present=_component_hash_field("alg"),
    ),
    ElementSpec(
        id="component-license",
        name="Component License",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.NEW_2026,
        cyclonedx_path="components[].licenses[]",
        description="License the component carries — new in 2026, tied to risk management.",
        remediation=(
            "Resolve licenses from the registry or model card (`aibom scan --resolve`), "
            "or declare them unknown."
        ),
        present=_component_license,
    ),
    ElementSpec(
        id="component-dependency-relationship",
        name="Component Dependency Relationship",
        scope=ElementScope.COMPONENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="dependencies[].ref / dependsOn",
        description=(
            "Explicit relationship for every component, including an explicit "
            "'no dependencies' statement for leaves."
        ),
        remediation="Emit a dependencies entry for every component, empty where it has none.",
        # Evaluated against the document's dependency graph; see _evaluate_component.
        present=lambda c: bool(c.get("__has_dependency_entry")),
    ),
)


def _metadata(doc: dict[str, Any]) -> dict[str, Any]:
    meta = doc.get("metadata")
    return meta if isinstance(meta, dict) else {}


# ── evaluation ───────────────────────────────────────────────────────────────


def evaluate_cyclonedx(doc: dict[str, Any]) -> MinimumElementsReport:
    """Score a CycloneDX document against the 2026 minimum elements."""
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise UnsupportedDocument(
            "not a CycloneDX document (this checker reads CycloneDX JSON; "
            "SPDX documents are not supported yet)"
        )

    components = _all_components(doc)
    dependency_refs = _dependency_refs(doc)
    for component in components:
        component["__has_dependency_entry"] = component.get("bom-ref") in dependency_refs

    doc_unknowns = _declared_unknowns(_metadata(doc).get("properties"))
    results = [_evaluate_document(doc, spec, doc_unknowns) for spec in _DOCUMENT_ELEMENTS]
    results.extend(_evaluate_component(components, spec) for spec in _COMPONENT_ELEMENTS)
    results.append(_evaluate_known_unknowns(results))
    results.append(_evaluate_coverage(doc, components))
    results.append(_evaluate_automation(doc))

    for component in components:
        component.pop("__has_dependency_entry", None)

    return MinimumElementsReport(
        document_format=f"{doc.get('bomFormat')} {doc.get('specVersion', '')}".strip(),
        components=len(components),
        transitive_components=sum(
            1 for c in components if _property(c, "aibom:dependency_scope") == "transitive"
        ),
        elements=results,
    )


def _evaluate_document(
    doc: dict[str, Any], spec: ElementSpec, declared: set[str]
) -> ElementResult:
    present = 1 if spec.present(doc) else 0
    unknown = 1 if not present and spec.id in declared else 0
    return _result(
        spec,
        applicable=1,
        present=present,
        declared=unknown,
        gaps=[] if present or unknown else ["(document)"],
    )


def _evaluate_component(components: list[dict[str, Any]], spec: ElementSpec) -> ElementResult:
    present = 0
    declared = 0
    gaps: list[str] = []
    for component in components:
        if spec.present(component):
            present += 1
        elif spec.id in _declared_unknowns(component.get("properties")):
            declared += 1
        elif len(gaps) < 10:
            gaps.append(str(component.get("name") or component.get("bom-ref") or "?"))
    return _result(
        spec, applicable=len(components), present=present, declared=declared, gaps=gaps
    )


def _evaluate_known_unknowns(results: Iterable[ElementResult]) -> ElementResult:
    """The 2026 baseline requires unknown data to be declared, not just absent."""
    results = list(results)
    gaps = [r.name for r in results if r.status is ElementStatus.MISSING]
    total_gaps = sum(r.applicable - r.present for r in results)
    declared = sum(r.declared_unknown for r in results)
    spec = ElementSpec(
        id="known-unknowns",
        name="Known Unknowns",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path=f"properties[{KNOWN_UNKNOWN_PROPERTY}]",
        description=(
            "Data that is unknown or withheld must be stated explicitly, so a "
            "consumer can tell a gap from a claim of completeness."
        ),
        remediation=(
            f"Emit a {KNOWN_UNKNOWN_PROPERTY} property naming the field and the reason "
            "for every value the generator could not determine."
        ),
        present=lambda _: True,
    )
    return _result(
        spec,
        applicable=max(total_gaps, 1),
        present=declared if total_gaps else 1,
        declared=0,
        gaps=gaps,
        # Every gap declared == satisfied; anything silent is a miss.
        override=(
            ElementStatus.SATISFIED
            if not gaps
            else ElementStatus.MISSING
        ),
    )


def _evaluate_coverage(doc: dict[str, Any], components: list[dict[str, Any]]) -> ElementResult:
    """2026 replaces 'depth' with 'coverage': all components, transitively."""
    primary = _metadata(doc).get("component")
    has_primary = isinstance(primary, dict) and _nonempty(primary.get("name"))
    declared_scope = _property_of_document(doc, "cisa:coverage")
    complete = declared_scope == "transitive"
    spec = ElementSpec(
        id="coverage",
        name="Coverage",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="metadata.component + components[] + properties[cisa:coverage]",
        description=(
            "Every component of the primary component, including transitive "
            "dependencies, with no depth limit (replaces the 2021 'depth' element)."
        ),
        remediation=(
            "Commit a lockfile so transitive dependencies are resolvable, and declare "
            "the achieved coverage in the document."
        ),
        present=lambda _: True,
    )
    gaps: list[str] = []
    if not has_primary:
        gaps.append("no primary component (metadata.component)")
    if not declared_scope:
        gaps.append("coverage not declared")
    status = (
        ElementStatus.SATISFIED
        if has_primary and complete
        else ElementStatus.PARTIAL
        if has_primary and declared_scope
        else ElementStatus.MISSING
    )
    return _result(
        spec,
        applicable=max(len(components), 1),
        present=len(components),
        declared=0,
        gaps=gaps,
        override=status,
    )


def _evaluate_automation(doc: dict[str, Any]) -> ElementResult:
    """Automation support: a machine-readable, widely used data format."""
    spec = ElementSpec(
        id="automation-support",
        name="Automation Support",
        scope=ElementScope.DOCUMENT,
        origin=ElementOrigin.UPDATED_2026,
        cyclonedx_path="bomFormat + specVersion",
        description=(
            "The SBOM is in a machine-readable format the baseline names as widely "
            "used — SPDX or CycloneDX. SWID tags were dropped in 2026."
        ),
        remediation="Distribute the SBOM as CycloneDX or SPDX JSON, not as a document or table.",
        present=lambda d: str(d.get("bomFormat", "")) in ACCEPTED_FORMATS
        and _nonempty(d.get("specVersion")),
    )
    ok = spec.present(doc)
    return _result(spec, applicable=1, present=int(ok), declared=0, gaps=[] if ok else ["format"])


def _result(
    spec: ElementSpec,
    *,
    applicable: int,
    present: int,
    declared: int,
    gaps: list[str],
    override: ElementStatus | None = None,
) -> ElementResult:
    if override is not None:
        status = override
    elif applicable == 0 or present == applicable:
        status = ElementStatus.SATISFIED
    elif present == 0 and declared == applicable:
        status = ElementStatus.DECLARED_UNKNOWN
    elif present + declared == applicable:
        status = ElementStatus.PARTIAL
    else:
        status = ElementStatus.MISSING
    return ElementResult(
        id=spec.id,
        name=spec.name,
        scope=spec.scope,
        origin=spec.origin,
        status=status,
        cyclonedx_path=spec.cyclonedx_path,
        description=spec.description,
        applicable=applicable,
        present=present,
        declared_unknown=declared,
        undeclared_gaps=gaps,
        remediation=spec.remediation,
    )


# ── document helpers ─────────────────────────────────────────────────────────


def _all_components(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Every component in the document, including nested ones and services."""
    out: list[dict[str, Any]] = []

    def walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if isinstance(item, dict):
                out.append(item)
                walk(item.get("components"))

    # The primary component is a component too: the baseline's data fields apply
    # to the software the SBOM describes, not only to its dependencies.
    walk([_metadata(doc).get("component")])
    walk(doc.get("components"))
    walk(doc.get("services"))
    return out


def _dependency_refs(doc: dict[str, Any]) -> set[str]:
    deps = doc.get("dependencies")
    if not isinstance(deps, list):
        return set()
    return {
        str(entry["ref"])
        for entry in deps
        if isinstance(entry, dict) and isinstance(entry.get("ref"), str)
    }


def _declared_unknowns(properties: Any) -> set[str]:
    """Field ids declared unknown via ``cisa:known-unknown`` properties."""
    declared: set[str] = set()
    if not isinstance(properties, list):
        return declared
    for prop in properties:
        if not isinstance(prop, dict) or prop.get("name") != KNOWN_UNKNOWN_PROPERTY:
            continue
        value = str(prop.get("value", ""))
        field_id = value.split(":", 1)[0].strip()
        if field_id:
            declared.add(field_id)
    return declared


def _property(component: dict[str, Any], name: str) -> str | None:
    for prop in component.get("properties", []) or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return str(prop.get("value"))
    return None


def _property_of_document(doc: dict[str, Any], name: str) -> str | None:
    return _property(_metadata(doc), name)
