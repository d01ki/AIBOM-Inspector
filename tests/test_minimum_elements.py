"""Tests for CISA 2026 SBOM minimum-elements conformance.

Two contracts are asserted here:

1. the exporter emits the document-level and component-level fields the 2026
   baseline requires, and *declares* the ones static analysis cannot know;
2. the evaluator scores an arbitrary CycloneDX document honestly — a silent gap
   is a failure, a declared unknown is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aibom.compliance.minimum_elements import (
    KNOWN_UNKNOWN_PROPERTY,
    ElementOrigin,
    ElementStatus,
    UnsupportedDocument,
    evaluate_cyclonedx,
)
from aibom.export.cyclonedx import SbomContext, to_cyclonedx
from aibom.inventory import Inventory
from aibom.service import run_scan

LOCKED_FIXTURE = Path(__file__).parent / "fixtures" / "locked-ai-app"


def _element(doc: dict[str, Any], element_id: str) -> Any:
    report = evaluate_cyclonedx(doc)
    return next(e for e in report.elements if e.id == element_id)


def _component(doc: dict[str, Any], name: str) -> dict[str, Any]:
    return next(c for c in doc["components"] if c["name"] == name)


def _unknowns(component: dict[str, Any]) -> set[str]:
    return {
        str(p["value"]).split(":", 1)[0]
        for p in component.get("properties", [])
        if p["name"] == KNOWN_UNKNOWN_PROPERTY
    }


# ── document-level elements ──────────────────────────────────────────────────


def test_document_elements_are_emitted(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory, context=SbomContext(author="Acme Security"))
    meta = doc["metadata"]
    assert meta["authors"] == [{"name": "Acme Security"}]
    assert meta["lifecycles"] == [{"phase": "pre-build"}]
    assert meta["tools"]["components"][0]["name"] == "aibom"
    assert meta["component"]["bom-ref"] == "aibom:primary-component"
    assert doc["version"] == 1
    assert meta["timestamp"]


def test_generation_context_is_overridable(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory, context=SbomContext(lifecycle="post-build"))
    assert doc["metadata"]["lifecycles"] == [{"phase": "post-build"}]
    assert _element(doc, "sbom-generation-context").status is ElementStatus.SATISFIED


def test_an_unknown_lifecycle_falls_back_instead_of_lying(
    fixture_inventory: Inventory,
) -> None:
    doc = to_cyclonedx(fixture_inventory, context=SbomContext(lifecycle="whenever"))
    assert doc["metadata"]["lifecycles"] == [{"phase": "pre-build"}]


def test_missing_author_is_declared_not_silent(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    author = _element(doc, "sbom-author")
    assert author.status is ElementStatus.DECLARED_UNKNOWN
    assert author.conformant


def test_signature_is_always_declared_unknown(fixture_inventory: Inventory) -> None:
    """The tool emits an unsigned document; it must say so rather than imply one."""
    doc = to_cyclonedx(fixture_inventory)
    signature = _element(doc, "sbom-author-signature")
    assert signature.status is ElementStatus.DECLARED_UNKNOWN
    assert signature.origin is ElementOrigin.NEW_2026


# ── component-level elements ─────────────────────────────────────────────────


def test_every_component_has_a_dependency_entry(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    refs = {entry["ref"] for entry in doc["dependencies"]}
    for component in doc["components"]:
        assert component["bom-ref"] in refs
    assert "aibom:primary-component" in refs
    assert _element(doc, "component-dependency-relationship").status is ElementStatus.SATISFIED


def test_leaf_components_declare_no_dependencies(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    leaves = [e for e in doc["dependencies"] if e["dependsOn"] == []]
    assert leaves, "a leaf must state 'no dependencies' explicitly"


def test_models_carry_a_purl_and_a_version() -> None:
    from aibom.inventory import ScanMetadata
    from aibom.models.entities import Model
    from aibom.models.evidence import Evidence

    ev = Evidence(
        file="app.py", line_start=1, line_end=1, snippet="x", matched_pattern="p"
    )
    inv = Inventory(metadata=ScanMetadata(tool_version="t", target="t"))
    inv.add_entity(
        Model(
            name="acme/llama-7b",
            provider="huggingface",
            revision="abc123",
            revision_pinned=True,
            license="Apache-2.0",
            author="acme",
            source_evidence=[ev],
        )
    )
    doc = to_cyclonedx(inv)
    model = _component(doc, "acme/llama-7b")
    assert model["version"] == "abc123"
    assert model["purl"] == "pkg:huggingface/acme/llama-7b@abc123"
    assert model["supplier"] == {"name": "acme"}
    assert model["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    # Weights are never downloaded, so the digest gap is declared.
    assert "component-hash" in _unknowns(model)


def test_prompts_carry_their_content_digest(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    prompts = [c for c in doc["components"] if c.get("hashes")]
    assert prompts, "prompt components should carry a SHA-256 content digest"
    for prompt in prompts:
        assert prompt["hashes"][0]["alg"] == "SHA-256"
        assert len(prompt["hashes"][0]["content"]) == 64


def test_an_unverifiable_digest_is_never_emitted() -> None:
    """A truncated hash would not survive recomputation, so it is not a hash."""
    from aibom.inventory import ScanMetadata
    from aibom.models.entities import Prompt
    from aibom.models.evidence import Evidence

    inv = Inventory(metadata=ScanMetadata(tool_version="t", target="t"))
    inv.add_entity(
        Prompt(
            name="sys",
            kind="system",
            content_hash="deadbeef",
            source_evidence=[
                Evidence(file="a.py", line_start=1, line_end=1, snippet="x", matched_pattern="p")
            ],
        )
    )
    prompt = _component(to_cyclonedx(inv), "sys")
    assert "hashes" not in prompt
    assert "component-hash" in _unknowns(prompt)


def test_lockfile_digests_reach_the_bom() -> None:
    result = run_scan(LOCKED_FIXTURE)
    doc = to_cyclonedx(result.inventory)
    openai = _component(doc, "openai")
    assert openai["hashes"][0]["alg"] == "SHA-512"
    assert openai["supplier"]["name"] == "registry.npmjs.org"
    assert openai["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    report = evaluate_cyclonedx(doc)
    assert report.transitive_components > 0
    assert _element(doc, "coverage").status is ElementStatus.SATISFIED


def test_coverage_is_partial_without_a_lockfile() -> None:
    """Manifests alone cannot reach transitive components — say so, don't imply it."""
    result = run_scan(Path(__file__).parent / "fixtures" / "vulnerable-ai-app")
    doc = to_cyclonedx(result.inventory)
    values = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert values["cisa:coverage"] == "declared-dependencies-only"
    assert _element(doc, "coverage").status is ElementStatus.PARTIAL


# ── evaluator ────────────────────────────────────────────────────────────────


def test_generated_bom_has_no_silent_gaps(fixture_inventory: Inventory) -> None:
    report = evaluate_cyclonedx(to_cyclonedx(fixture_inventory))
    silent = [e.name for e in report.elements if e.status is ElementStatus.MISSING]
    assert silent == []
    assert report.conformant


def test_a_bare_bom_fails_on_undeclared_gaps() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
        "components": [{"type": "library", "bom-ref": "a", "name": "left-pad"}],
    }
    report = evaluate_cyclonedx(doc)
    assert not report.conformant
    missing = {e.id for e in report.elements if e.status is ElementStatus.MISSING}
    assert {"component-hash", "component-license", "known-unknowns"} <= missing
    assert "left-pad" in _element(doc, "component-hash").undeclared_gaps


def test_declaring_a_gap_makes_it_conformant() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
        "components": [
            {
                "type": "library",
                "bom-ref": "a",
                "name": "left-pad",
                "properties": [
                    {"name": KNOWN_UNKNOWN_PROPERTY, "value": "component-hash: no lockfile"}
                ],
            }
        ],
    }
    assert _element(doc, "component-hash").status is ElementStatus.DECLARED_UNKNOWN


def test_partial_coverage_is_reported_per_component() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
        "components": [
            {"type": "library", "bom-ref": "a", "name": "a", "version": "1.0"},
            {"type": "library", "bom-ref": "b", "name": "b"},
        ],
    }
    version = _element(doc, "component-version")
    assert version.status is ElementStatus.MISSING
    assert version.present == 1
    assert version.applicable == 2


def test_bom_ref_is_not_a_software_identifier() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
        "components": [{"type": "library", "bom-ref": "pkg:npm/left-pad", "name": "left-pad"}],
    }
    assert _element(doc, "component-identifier").status is ElementStatus.MISSING


def test_a_signed_third_party_bom_is_recognized() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 2,
        "metadata": {
            "timestamp": "2026-07-29T00:00:00Z",
            "authors": [{"name": "Vendor"}],
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "name": "their-tool"}]},
            "component": {"type": "application", "bom-ref": "root", "name": "product"},
            "properties": [{"name": "cisa:coverage", "value": "transitive"}],
        },
        "components": [],
        "signature": {"algorithm": "Ed25519", "value": "aGk="},
    }
    assert _element(doc, "sbom-author-signature").status is ElementStatus.SATISFIED
    assert _element(doc, "sbom-version").status is ElementStatus.SATISFIED
    assert _element(doc, "sbom-author").status is ElementStatus.SATISFIED
    assert _element(doc, "coverage").status is ElementStatus.SATISFIED
    # The primary component itself is scored: this vendor declares no digest.
    assert _element(doc, "component-hash").undeclared_gaps == ["product"]


def test_non_cyclonedx_documents_are_rejected() -> None:
    with pytest.raises(UnsupportedDocument):
        evaluate_cyclonedx({"spdxVersion": "SPDX-2.3"})


def test_report_serializes_with_its_summary(fixture_inventory: Inventory) -> None:
    payload = evaluate_cyclonedx(to_cyclonedx(fixture_inventory)).to_dict()
    assert payload["summary"]["total"] == len(payload["elements"])
    assert payload["conformant"] is True
    assert payload["standard"].startswith("CISA 2026")
