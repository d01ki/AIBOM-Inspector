"""Evidence-backed links between AI components and the packages they use.

Each edge must cite a real line in the scanned repository; anything the files
do not prove stays unlinked (the negative tests matter as much as the positive).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.graph import build_graph
from aibom.inventory import Inventory
from aibom.service import run_scan

FIXTURES = Path(__file__).parent / "fixtures"


def _named_edges(inv: Inventory) -> set[tuple[str, str, str]]:
    by_id = {e.id: e for e in inv.entities}
    return {
        (by_id[r.source_id].name, r.relationship.value, by_id[r.target_id].name)
        for r in inv.relationships
    }


@pytest.fixture(scope="module")
def py_app() -> Inventory:
    return run_scan(FIXTURES / "vulnerable-ai-app").inventory


@pytest.fixture(scope="module")
def ts_agent() -> Inventory:
    return run_scan(FIXTURES / "vulnerable-ts-agent").inventory


def test_model_is_served_by_its_provider_service(py_app: Inventory) -> None:
    assert ("gpt-4o-mini", "served_by", "openai") in _named_edges(py_app)


def test_model_depends_on_the_imported_sdk(py_app: Inventory) -> None:
    edges = _named_edges(py_app)
    assert ("gpt-4o-mini", "depends_on", "openai") in edges
    assert ("bert-base-uncased", "depends_on", "transformers") in edges
    assert ("mistralai/Mistral-7B-Instruct-v0.2", "depends_on", "langchain-huggingface") in edges


def test_dataset_links_to_the_loader_not_the_model_library(py_app: Inventory) -> None:
    edges = _named_edges(py_app)
    assert ("imdb", "depends_on", "datasets") in edges
    assert ("imdb", "depends_on", "transformers") not in edges
    assert ("bert-base-uncased", "depends_on", "datasets") not in edges


def test_provider_family_is_respected(py_app: Inventory) -> None:
    """app.py imports openai and transformers; an OpenAI model gets only openai."""
    edges = _named_edges(py_app)
    assert ("gpt-4o-mini", "depends_on", "transformers") not in edges
    assert ("bert-base-uncased", "depends_on", "openai") not in edges


def test_link_evidence_is_the_import_line(py_app: Inventory) -> None:
    by_id = {e.id: e for e in py_app.entities}
    for rel in py_app.relationships:
        if (by_id[rel.source_id].name, by_id[rel.target_id].name) != ("gpt-4o-mini", "openai"):
            continue
        if rel.relationship.value != "depends_on":
            continue
        (ev,) = rel.source_evidence
        line = (FIXTURES / "vulnerable-ai-app" / ev.file).read_text(encoding="utf-8")
        assert line.splitlines()[ev.line_start - 1].strip() == "import openai"
        assert ev.kind == "link"
        return
    pytest.fail("gpt-4o-mini -> openai depends_on edge missing")


def test_typescript_links_scoped_packages(ts_agent: Inventory) -> None:
    edges = _named_edges(ts_agent)
    assert ("claude-sonnet-4-5", "served_by", "anthropic") in edges
    assert ("claude-sonnet-4-5", "depends_on", "@anthropic-ai/sdk") in edges
    assert ("gpt-4.1", "depends_on", "@ai-sdk/openai") in edges
    assert ("claude-sonnet-4-5", "depends_on", "openai") not in edges


def test_no_import_means_no_edge() -> None:
    """agent.rs / Agent.java call a model without importing an SDK: unlinked."""
    inv = run_scan(FIXTURES / "multi-language-agent").inventory
    edges = _named_edges(inv)
    assert not any(src == "claude-sonnet-4-5" and kind == "depends_on" for src, kind, _ in edges)
    assert ("gpt-4.1", "depends_on", "github.com/sashabaranov/go-openai") in edges


def test_cross_file_service_links_to_package() -> None:
    inv = run_scan(FIXTURES / "xfile-py-candidate").inventory
    assert ("openai", "depends_on", "openai-agents") in _named_edges(inv)
    graph = build_graph(inv, [])
    linked = {e["source"] for e in graph["edges"]} | {e["target"] for e in graph["edges"]}
    assert {n["id"] for n in graph["nodes"]} <= linked, "no isolated node expected"


def test_colocation_edges_cite_a_real_line(py_app: Inventory) -> None:
    for rel in py_app.relationships:
        for ev in rel.source_evidence:
            assert ev.file != "<inferred>"
            assert (FIXTURES / "vulnerable-ai-app" / ev.file).is_file()


def test_linker_never_leaves_the_scan_root(tmp_path: Path) -> None:
    from aibom.linking import _SourceReader

    (tmp_path / "inside.py").write_text("import openai\n", encoding="utf-8")
    reader = _SourceReader(tmp_path)
    assert reader.lines("inside.py") == ["import openai"]
    assert reader.lines("../outside.py") is None
