"""Tests for the CycloneDX 1.6 (ML-BOM) exporter.

Assert the document is structurally valid CycloneDX and that AIBOM-specific data
survives the round trip in the ``aibom:*`` property namespace.
"""

from __future__ import annotations

import json

from aibom import __version__
from aibom.export.cyclonedx import to_cyclonedx, to_cyclonedx_json
from aibom.inventory import Inventory


def _props(component: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def test_document_envelope(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["tools"]["components"][0]["name"] == "aibom"
    assert doc["metadata"]["tools"]["components"][0]["version"] == __version__


def test_serial_number_is_deterministic(fixture_inventory: Inventory) -> None:
    a = to_cyclonedx(fixture_inventory)["serialNumber"]
    b = to_cyclonedx(fixture_inventory)["serialNumber"]
    assert a == b


def test_models_are_ml_components(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    ml = [c for c in doc["components"] if c["type"] == "machine-learning-model"]
    names = {c["name"] for c in ml}
    assert "bert-base-uncased" in names
    assert "acme-ai/llama-7b-hf" in names


def test_component_types_are_valid(fixture_inventory: Inventory) -> None:
    valid = {"machine-learning-model", "data", "application", "library"}
    for comp in to_cyclonedx(fixture_inventory)["components"]:
        assert comp["type"] in valid, comp


def test_bom_refs_are_unique(fixture_inventory: Inventory) -> None:
    refs = [c["bom-ref"] for c in to_cyclonedx(fixture_inventory)["components"]]
    assert len(refs) == len(set(refs))


def test_services_are_separated(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    svc_names = {s["name"] for s in doc.get("services", [])}
    assert "openai" in svc_names
    # services must not leak into components
    assert all(c["type"] != "service" for c in doc["components"])


def test_dependencies_reference_known_refs(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    known = {c["bom-ref"] for c in doc["components"]}
    known |= {s["bom-ref"] for s in doc.get("services", [])}
    for dep in doc.get("dependencies", []):
        assert dep["ref"] in known
        for t in dep["dependsOn"]:
            assert t in known


def test_evidence_travels_as_properties(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    ml = next(c for c in doc["components"] if c["name"] == "bert-base-uncased")
    props = _props(ml)
    assert "aibom:evidence" in props
    assert any(":" in v for v in props["aibom:evidence"])  # path:line form
    assert props["aibom:provider"] == ["huggingface"]


def test_pickle_format_surfaced(fixture_inventory: Inventory) -> None:
    doc = to_cyclonedx(fixture_inventory)
    pickled = [
        c for c in doc["components"]
        if "pkl" in ",".join(_props(c).get("aibom:formats", []))
    ]
    assert pickled, "expected the .pkl weight file to surface aibom:formats=pkl"


def test_json_is_serializable(fixture_inventory: Inventory) -> None:
    text = to_cyclonedx_json(fixture_inventory)
    parsed = json.loads(text)
    assert parsed["bomFormat"] == "CycloneDX"


def test_license_id_vs_name() -> None:
    from aibom.export.cyclonedx import _licenses

    assert _licenses("apache-2.0") == [{"license": {"id": "Apache-2.0"}}]
    assert _licenses("some-custom-license") == [{"license": {"name": "some-custom-license"}}]
    assert _licenses(None) is None
