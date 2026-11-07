"""Package -> package dependency edges resolved from lockfiles.

A lockfile records the resolved graph, not just the component list. Without
these edges the dependency map of a locked project is a set of isolated nodes
and the CycloneDX ``dependencies`` section claims every package is a leaf.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom.collectors.lockfiles import LockfileCollector
from aibom.export.cyclonedx import to_cyclonedx
from aibom.graph import build_graph
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import EntityType, Package, RelationshipType
from aibom.service import run_scan

FIXTURE = Path(__file__).parent / "fixtures" / "locked-ai-app"


def _collect(root: Path) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version="test", target=str(root)))
    LockfileCollector(root).collect(inv)
    return inv


def _edges(inv: Inventory) -> set[tuple[str, str, str]]:
    """``(ecosystem, parent, child)`` for every DEPENDS_ON edge."""
    by_id = {e.id: e for e in inv.entities}
    out: set[tuple[str, str, str]] = set()
    for rel in inv.relationships:
        if rel.relationship is not RelationshipType.DEPENDS_ON:
            continue
        src, dst = by_id[rel.source_id], by_id[rel.target_id]
        assert isinstance(src, Package) and isinstance(dst, Package)
        assert src.ecosystem == dst.ecosystem
        out.add((src.ecosystem or "", src.name, dst.name))
    return out


@pytest.fixture(scope="module")
def locked() -> Inventory:
    return _collect(FIXTURE)


@pytest.mark.parametrize(
    ("ecosystem", "parent", "child"),
    [
        ("npm", "openai", "form-data-encoder"),
        ("PyPI", "transformers", "tokenizers"),
        ("PyPI", "anthropic", "httpx"),
        ("crates.io", "locked-ai-app", "candle-core"),
        ("RubyGems", "ruby-openai", "faraday"),
        ("RubyGems", "ruby-openai", "event_stream_parser"),
    ],
)
def test_lockfile_edges_are_resolved(
    locked: Inventory, ecosystem: str, parent: str, child: str
) -> None:
    assert (ecosystem, parent, child) in _edges(locked)


def test_edges_point_at_the_declaring_lockfile_line(locked: Inventory) -> None:
    by_id = {e.id: e for e in locked.entities}
    for rel in locked.relationships:
        src = by_id[rel.source_id]
        if src.name != "transformers":
            continue
        (ev,) = rel.source_evidence
        assert ev.file == "poetry.lock"
        text = (FIXTURE / "poetry.lock").read_text(encoding="utf-8").splitlines()
        assert "tokenizers" in text[ev.line_start - 1]
        assert ev.kind == "lockfile"
        return
    pytest.fail("transformers has no dependency edge")


def test_unresolved_requirements_never_become_edges(locked: Inventory) -> None:
    edges = _edges(locked)
    # composer: platform requirements and packages absent from the lock.
    assert not any(parent == "openai-php/client" for _, parent, _ in edges)
    # poetry: "Requests" is not locked in poetry.lock. requirements.txt pins
    # requests, but a lockfile only speaks for the packages it resolved.
    assert ("PyPI", "transformers", "requests") not in edges


def test_no_self_or_cross_ecosystem_edges(locked: Inventory) -> None:
    for _, parent, child in _edges(locked):
        assert parent != child


def test_pypi_names_are_normalized(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        "[[package]]\n"
        'name = "langchain-core"\n'
        'version = "0.2.0"\n\n'
        "[package.dependencies]\n"
        'PyYAML = ">=5.3"\n'
        'jsonpatch = { version = ">=1.33", optional = true }\n\n'
        "[[package]]\n"
        'name = "pyyaml"\n'
        'version = "6.0.1"\n\n'
        "[[package]]\n"
        'name = "jsonpatch"\n'
        'version = "1.33"\n',
        encoding="utf-8",
    )
    edges = _edges(_collect(tmp_path))
    assert ("PyPI", "langchain-core", "pyyaml") in edges
    assert ("PyPI", "langchain-core", "jsonpatch") in edges


def test_npm_v1_uses_requires(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "openai": {"version": "3.3.0", "requires": {"axios": "^0.26.0"}},
                    "axios": {"version": "0.26.1"},
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    assert _edges(_collect(tmp_path)) == {("npm", "openai", "axios")}


def test_cargo_versioned_dependency_strings(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        "version = 3\n\n"
        "[[package]]\n"
        'name = "app"\n'
        'version = "0.1.0"\n'
        'dependencies = [\n "serde 1.0.1 (registry+https://github.com/rust-lang/crates.io-index)",\n]\n\n'
        "[[package]]\n"
        'name = "serde"\n'
        'version = "1.0.1"\n',
        encoding="utf-8",
    )
    assert _edges(_collect(tmp_path)) == {("crates.io", "app", "serde")}


def test_pipfile_lock_has_no_graph(tmp_path: Path) -> None:
    """Pipfile.lock flattens the graph: no edges, and none are invented."""
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"a": {"version": "==1"}, "b": {"version": "==2"}}}),
        encoding="utf-8",
    )
    inv = _collect(tmp_path)
    assert len(inv.by_type(EntityType.PACKAGE)) == 2
    assert inv.relationships == []


def test_cyclonedx_carries_the_lockfile_graph() -> None:
    result = run_scan(FIXTURE)
    bom = to_cyclonedx(result.inventory)
    by_ref = {c["bom-ref"]: c["name"] for c in bom["components"]}
    depends = {
        by_ref[d["ref"]]: {by_ref[t] for t in d["dependsOn"]}
        for d in bom["dependencies"]
        if d["ref"] in by_ref
    }
    assert "form-data-encoder" in depends["openai"]
    assert "tokenizers" in depends["transformers"]


def test_graph_keeps_dependency_edges_of_ai_packages() -> None:
    """A plain transitive package an AI package depends on is shown with its edge."""
    result = run_scan(FIXTURE)
    graph = build_graph(result.inventory, result.findings)
    labels = {n["id"]: n["label"] for n in graph["nodes"]}
    pairs = {
        (labels[e["source"]], labels[e["target"]])
        for e in graph["edges"]
        if e["type"] == "depends_on"
    }
    assert ("openai", "form-data-encoder") in pairs
    assert ("transformers", "tokenizers") in pairs


def test_graph_shows_one_hop_of_plain_dependencies_and_no_dangling_edges() -> None:
    result = run_scan(FIXTURE)
    graph = build_graph(result.inventory, result.findings)
    ids = {n["id"] for n in graph["nodes"]}
    labels = {n["label"] for n in graph["nodes"]}
    # Pulled in directly by an AI package: drawn.
    assert {"form-data-encoder", "faraday", "httpx"} <= labels
    # The Cargo root crate is a plain package nothing AI depends on: hidden,
    # and so is its edge to candle-core (which is drawn as an AI package).
    assert "locked-ai-app" not in labels
    assert "candle-core" in labels
    for edge in graph["edges"]:
        assert edge["source"] in ids and edge["target"] in ids
        assert edge["evidence"], "every drawn edge cites a location"


def test_html_report_draws_directed_edges() -> None:
    from aibom.report.html import render_html

    result = run_scan(FIXTURE)
    html = render_html(result.inventory, result.findings, result.score)
    assert "marker-end='url(#graph-arrow)'" in html
    assert "openai depends on form-data-encoder (package-lock.json:" in html


# --- review backlog #37: the dependency table lists every package -------------

def test_dependency_list_keeps_plain_packages_and_marks_unknown_relations(
    tmp_path: Path,
) -> None:
    from aibom.graph import build_dependency_list, build_graph
    from aibom.service import run_scan

    (tmp_path / "requirements.txt").write_text(
        "openai-agents==0.1.0\nfastapi==0.110.0\npydantic==2.6.0\n", encoding="utf-8"
    )
    result = run_scan(tmp_path)
    table = build_dependency_list(result.inventory, result.findings)
    names = {row["name"] for row in table["packages"]}
    assert {"fastapi", "pydantic", "openai-agents"} <= names
    assert table["summary"]["total"] == 3
    assert table["summary"]["relations_resolved"] == 0
    assert all(row["relations"] == "unknown" for row in table["packages"])
    assert all(row["depends_on"] == [] for row in table["packages"])  # no invented edges
    # The AI usage graph still filters plain packages; the table does not.
    graph_names = {n["label"] for n in build_graph(result.inventory, result.findings)["nodes"]}
    assert "fastapi" not in graph_names


def test_dependency_list_reports_lockfile_edges_with_evidence(tmp_path: Path) -> None:
    from aibom.graph import build_dependency_list
    from aibom.service import run_scan

    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n\n'
        '[package.dependencies]\nwerkzeug = ">=3.0"\n\n'
        '[[package]]\nname = "werkzeug"\nversion = "3.0.1"\n',
        encoding="utf-8",
    )
    result = run_scan(tmp_path)
    table = build_dependency_list(result.inventory, result.findings)
    rows = {row["name"]: row for row in table["packages"]}
    assert rows["flask"]["relations"] == "resolved"
    assert rows["flask"]["depends_on"] == [rows["werkzeug"]["id"]]
    assert rows["werkzeug"]["required_by"] == [rows["flask"]["id"]]
    assert rows["flask"]["edge_evidence"][rows["werkzeug"]["id"]].startswith("poetry.lock:")
    assert table["summary"]["graph_lockfiles"] == ["poetry.lock"]
