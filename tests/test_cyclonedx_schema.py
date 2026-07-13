"""Validate exported AIBOMs against the *official* CycloneDX 1.6 JSON schema.

This is the SPEC §7/§9 acceptance metric: the AIBOM must be schema-valid so it
is accepted by ecosystem tooling (e.g. Dependency-Track). Validation uses the
schema bundled in ``cyclonedx-python-lib``.
"""

from __future__ import annotations

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
