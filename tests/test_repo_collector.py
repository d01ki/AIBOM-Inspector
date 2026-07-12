"""Golden-fixture tests for the repository collector.

These assert known-good findings against tests/fixtures/vulnerable-ai-app.
The zero-false-negative contract of the tool lives here.
"""

from __future__ import annotations

from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory
from aibom.models.entities import EntityType
from tests.conftest import FIXTURE


def _names(inv: Inventory, etype: EntityType) -> set[str]:
    return {e.name for e in inv.by_type(etype)}


def test_models_discovered(fixture_inventory: Inventory) -> None:
    names = _names(fixture_inventory, EntityType.MODEL)
    assert "bert-base-uncased" in names
    assert "acme-ai/llama-7b-hf" in names
    assert "distilbert/distilbert-base-uncased" in names
    assert "mistralai/Mistral-7B-Instruct-v0.2" in names
    assert "gpt-4o-mini" in names


def test_pickle_weight_file_detected(fixture_inventory: Inventory) -> None:
    pickles = [
        m for m in fixture_inventory.by_type(EntityType.MODEL)
        if getattr(m, "formats", None) and "pkl" in m.formats
    ]
    assert len(pickles) == 1
    assert pickles[0].name.endswith("classifier.pkl")
    assert pickles[0].provider == "local"  # type: ignore[attr-defined]


def test_dataset_discovered(fixture_inventory: Inventory) -> None:
    assert "imdb" in _names(fixture_inventory, EntityType.DATASET)


def test_prompts_discovered(fixture_inventory: Inventory) -> None:
    prompts = fixture_inventory.by_type(EntityType.PROMPT)
    kinds = {p.kind for p in prompts}  # type: ignore[attr-defined]
    assert "system" in kinds  # hardcoded SYSTEM_PROMPT / role:system
    assert "template" in kinds  # prompts/agent_system.prompt file


def test_services_discovered(fixture_inventory: Inventory) -> None:
    names = _names(fixture_inventory, EntityType.SERVICE)
    assert "openai" in names
    assert any(n.startswith("https://api.openai.com") for n in names)


def test_agents_discovered(fixture_inventory: Inventory) -> None:
    agents = fixture_inventory.by_type(EntityType.AGENT)
    assert agents, "expected at least one agent from create_react_agent/AgentExecutor"
    assert all(a.framework == "langchain" for a in agents)  # type: ignore[attr-defined]


def test_provider_pinning(fixture_inventory: Inventory) -> None:
    models = fixture_inventory.by_type(EntityType.MODEL)
    bert = next(m for m in models if m.name == "bert-base-uncased")
    assert bert.provider == "huggingface"  # type: ignore[attr-defined]
    # none of the fixture's from_pretrained calls pin a revision
    assert bert.revision_pinned is False  # type: ignore[attr-defined]


def test_every_entity_has_evidence(fixture_inventory: Inventory) -> None:
    for entity in fixture_inventory.entities:
        assert entity.source_evidence, f"{entity.name} has no evidence"
        for ev in entity.source_evidence:
            assert 0.0 <= ev.confidence <= 1.0


def test_agent_relationships_created(fixture_inventory: Inventory) -> None:
    # agent.py co-locates an agent with a model -> at least one INVOKES edge
    assert fixture_inventory.relationships


def test_scan_is_idempotent(fixture_inventory: Inventory) -> None:
    before = len(fixture_inventory.entities)
    RepoCollector(FIXTURE).collect(fixture_inventory)
    assert len(fixture_inventory.entities) == before
