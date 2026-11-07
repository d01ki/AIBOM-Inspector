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


# ── MCP servers, their tools, and what launches them ─────────────────────────

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture(scope="module")
def mcp_app() -> Inventory:
    return run_scan(EXAMPLES / "mcp-tool-exposure" / "candidate").inventory


def _edge(inv: Inventory, src: str, kind: str, tgt: str) -> object:
    by_id = {e.id: e for e in inv.entities}
    for rel in inv.relationships:
        if (by_id[rel.source_id].name, rel.relationship.value, by_id[rel.target_id].name) == (
            src, kind, tgt
        ):
            return rel
    raise AssertionError(f"missing edge {src} {kind} {tgt}")


SERVER = "mcp-server@servers/storage_server.py"


def test_mcp_tools_are_served_by_the_server_in_their_file(mcp_app: Inventory) -> None:
    for tool, line in (("read_asset", 17), ("purge_asset", 23), ("run_maintenance", 30)):
        rel = _edge(mcp_app, f"{tool}@servers/storage_server.py", "served_by", SERVER)
        ev = rel.source_evidence[0]  # type: ignore[attr-defined]
        assert (ev.file, ev.line_start) == ("servers/storage_server.py", line)


def test_mcp_server_depends_on_the_imported_sdk(mcp_app: Inventory) -> None:
    rel = _edge(mcp_app, SERVER, "depends_on", "mcp")
    assert rel.source_evidence[0].line_start == 9  # type: ignore[attr-defined]
    edges = _named_edges(mcp_app)
    assert (SERVER, "depends_on", "openai-agents") not in edges


def test_mcp_config_and_agent_launch_the_server_they_name(mcp_app: Inventory) -> None:
    config = _edge(mcp_app, "mcp-config@.mcp.json", "invokes", SERVER)
    assert config.source_evidence[0].location() == ".mcp.json:5"  # type: ignore[attr-defined]
    agent = _edge(mcp_app, "agent-instructions@app/agent.py:13", "invokes", SERVER)
    assert agent.source_evidence[0].location() == "app/agent.py:8"  # type: ignore[attr-defined]


def test_mcp_demo_graph_has_no_isolated_component_but_the_unused_sdk(
    mcp_app: Inventory,
) -> None:
    graph = build_graph(mcp_app, [])
    linked = {e["source"] for e in graph["edges"]} | {e["target"] for e in graph["edges"]}
    isolated = {n["label"] for n in graph["nodes"] if n["id"] not in linked}
    # openai-agents is imported by agent.py, but no model is named there, so
    # nothing proves which component uses it: it stays unlinked, not guessed.
    assert isolated == {"openai-agents"}


def test_a_similar_file_name_does_not_launch_the_server(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
        "@mcp.tool()\ndef ping() -> str:\n    return 'pong'\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("mcp==1.9.0\n", encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"x": {"command": "python",\n "args": ["my_server.py"]}}}\n',
        encoding="utf-8",
    )
    edges = _named_edges(run_scan(tmp_path).inventory)
    assert not any(kind == "invokes" and tgt.startswith("mcp-server@") for _, kind, tgt in edges)
    assert ("ping@server.py", "served_by", "mcp-server@server.py") in edges


def test_prompt_tool_bindings_cite_the_agent_constructor() -> None:
    inv = run_scan(FIXTURES / "xfile-py-candidate").inventory
    rel = _edge(inv, "agent-instructions@assistant/main.py:12", "invokes",
                "run_diagnostic@tools/executor.py")
    ev = rel.source_evidence[0]  # type: ignore[attr-defined]
    assert ev.file == "assistant/main.py" and ev.matched_pattern == "agent-tool-binding"
    for any_rel in inv.relationships:
        assert any_rel.source_evidence, f"edge without evidence: {any_rel}"
