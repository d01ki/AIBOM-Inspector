"""Validate exported AIBOMs against the *official* CycloneDX 1.6 JSON schema.

This is the acceptance metric for the export: the AIBOM must be schema-valid so it
is accepted by ecosystem tooling (e.g. Dependency-Track). Validation uses the
schema bundled in ``cyclonedx-python-lib``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom import __version__
from aibom.export.cyclonedx import to_cyclonedx_json
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import (
    Agent,
    Dataset,
    Model,
    Package,
    Prompt,
    Relationship,
    RelationshipType,
    Service,
)
from aibom.models.evidence import Evidence

# Skip cleanly if the optional validation dep is unavailable.
validation = pytest.importorskip("cyclonedx.validation.json")
schema = pytest.importorskip("cyclonedx.schema")

_VALIDATOR = validation.JsonStrictValidator(schema.SchemaVersion.V1_6)


def _assert_valid(json_str: str) -> None:
    error = _VALIDATOR.validate_str(json_str)
    assert error is None, f"CycloneDX 1.6 schema violation: {error!r}"


def _ev() -> Evidence:
    return Evidence(
        file="a.py", line_start=1, line_end=2, snippet="x",
        matched_pattern="p", confidence=0.9,
    )


def test_fixture_bom_is_schema_valid(fixture_inventory: Inventory) -> None:
    _assert_valid(to_cyclonedx_json(fixture_inventory))


def test_empty_bom_is_schema_valid() -> None:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    _assert_valid(to_cyclonedx_json(inv))


def test_fully_resolved_bom_is_schema_valid() -> None:
    """Exercise every field: resolved+gated model card, SPDX + free-text licenses,
    all entity types, services, and a dependency graph."""
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    model = Model(
        name="acme/llama", provider="huggingface", revision="abc123", revision_pinned=True,
        formats=["safetensors", "pickle"], license="apache-2.0", author="acme",
        has_model_card=True, downloads=1000, gated=True,
        last_modified="2025-01-01T00:00:00Z", resolved=True, source_evidence=[_ev()],
    )
    weird_license = Model(
        name="acme/custom", provider="huggingface", license="my-proprietary-license",
        resolved=True, source_evidence=[_ev()],
    )
    dataset = Dataset(
        name="acme/data", source="huggingface", license="mit", provenance="hf: acme",
        author="acme", downloads=5, resolved=True, source_evidence=[_ev()],
    )
    prompt = Prompt(name="sys", kind="system", content_hash="deadbeef", source_evidence=[_ev()])
    agent = Agent(name="agent@x", framework="langchain", tools=["search"], source_evidence=[_ev()])
    service = Service(
        name="openai", kind="api", endpoint="https://api.openai.com", source_evidence=[_ev()]
    )
    package = Package(
        name="transformers", ecosystem="PyPI", version="4.40.0", version_pinned=True,
        source_evidence=[_ev()],
    )
    npm_pkg = Package(
        name="@anthropic-ai/sdk", ecosystem="npm", version="0.20.0", version_pinned=True,
        source_evidence=[_ev()],
    )
    for e in (model, weird_license, dataset, prompt, agent, service, package, npm_pkg):
        inv.add_entity(e)
    inv.add_relationship(Relationship(
        source_id=agent.id, target_id=model.id,
        relationship=RelationshipType.INVOKES, source_evidence=[_ev()],
    ))
    inv.add_relationship(Relationship(
        source_id=agent.id, target_id=service.id,
        relationship=RelationshipType.INVOKES, source_evidence=[_ev()],
    ))
    _assert_valid(to_cyclonedx_json(inv))


@pytest.mark.parametrize(
    "fixture", ["xfile-py-candidate", "xfile-ts-candidate", "xfile-py-baseline"]
)
def test_cross_file_demo_boms_are_schema_valid(fixture: str) -> None:
    import json
    from pathlib import Path

    from aibom.service import run_scan

    root = Path(__file__).parent / "fixtures" / fixture
    document = to_cyclonedx_json(run_scan(root).inventory)
    _assert_valid(document)
    properties = {
        prop["name"]: prop["value"]
        for component in json.loads(document)["components"]
        for prop in component.get("properties", [])
    }
    assert properties.get("aibom:prompt_flow_cross_file") == "true"
    if fixture.endswith("candidate"):
        assert properties.get("aibom:prompt_flow_evidence_level") == "proven_static"


# --- one name in two ecosystems is two components -------------------------------

def _two_ecosystems(tmp_path: Path) -> Inventory:
    from aibom.service import run_scan

    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(
        '{"dependencies": {"dotenv": "16.0.0"}}\n', encoding="utf-8"
    )
    (tmp_path / "cli").mkdir()
    (tmp_path / "cli" / "Gemfile").write_text(
        'source "https://rubygems.org"\ngem "dotenv", "3.2.0"\n', encoding="utf-8"
    )
    return run_scan(tmp_path).inventory


def test_same_name_in_two_ecosystems_gets_two_ids_and_a_valid_bom(tmp_path: Path) -> None:
    """modelcontextprotocol/quickstart-resources: dotenv on npm and on RubyGems.

    Packages dedupe per ecosystem, but the id ignored the ecosystem, so both got
    one bom-ref and the root's dependsOn listed it twice (schema-invalid).
    """
    inventory = _two_ecosystems(tmp_path)
    dotenv = [e for e in inventory.entities if isinstance(e, Package) and e.name == "dotenv"]
    assert sorted(p.ecosystem or "" for p in dotenv) == ["RubyGems", "npm"]
    assert dotenv[0].id != dotenv[1].id
    ids = [e.id for e in inventory.entities]
    assert len(ids) == len(set(ids))
    document = to_cyclonedx_json(inventory)
    _assert_valid(document)
    refs = [c["bom-ref"] for c in json.loads(document)["components"]]
    assert len(refs) == len(set(refs))


def test_one_package_in_one_ecosystem_keeps_one_id(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    for sub in ("a", "b"):
        (tmp_path / sub / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    from aibom.service import run_scan

    packages = [e for e in run_scan(tmp_path).inventory.entities
                if isinstance(e, Package) and e.name == "openai"]
    assert len(packages) == 1  # still merged
    assert len({ev.file for ev in packages[0].source_evidence}) == 2


def test_ids_of_other_components_do_not_change() -> None:
    import hashlib

    model = Model(name="gpt-4o", provider="openai")
    digest = hashlib.sha256(b"model\x1fgpt-4o").hexdigest()[:12]
    assert model.id == f"model:{digest}"
