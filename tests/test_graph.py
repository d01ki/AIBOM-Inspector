"""Tests for the dependency-graph builder."""

from __future__ import annotations

from aibom.graph import build_graph
from aibom.inventory import Inventory
from aibom.risk.engine import evaluate


def _graph(inv: Inventory) -> dict:
    return build_graph(inv, evaluate(inv))


def test_one_node_per_entity(fixture_inventory: Inventory) -> None:
    g = _graph(fixture_inventory)
    assert len(g["nodes"]) == len(fixture_inventory.entities)
    ids = {n["id"] for n in g["nodes"]}
    assert len(ids) == len(g["nodes"])  # unique


def test_edges_reference_known_nodes(fixture_inventory: Inventory) -> None:
    g = _graph(fixture_inventory)
    ids = {n["id"] for n in g["nodes"]}
    assert g["edges"], "fixture co-locates an agent with targets -> edges expected"
    for e in g["edges"]:
        assert e["source"] in ids
        assert e["target"] in ids
        assert e["type"]


def test_node_carries_worst_severity(fixture_inventory: Inventory) -> None:
    g = _graph(fixture_inventory)
    pkl = next(n for n in g["nodes"] if n["label"].endswith("classifier.pkl"))
    assert pkl["severity"] == "high"  # TDR-001 pickle
    assert pkl["finding_count"] >= 1


def test_clean_nodes_have_no_severity(fixture_inventory: Inventory) -> None:
    g = _graph(fixture_inventory)
    # prompts have no rules against them -> severity None
    prompt = next(n for n in g["nodes"] if n["type"] == "prompt")
    assert prompt["severity"] is None
    assert prompt["finding_count"] == 0


def test_node_shape(fixture_inventory: Inventory) -> None:
    g = _graph(fixture_inventory)
    node = g["nodes"][0]
    assert set(node) >= {"id", "label", "type", "severity", "finding_count", "location"}


def test_empty_inventory_graph() -> None:
    from aibom import __version__
    from aibom.inventory import ScanMetadata

    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    g = build_graph(inv, [])
    assert g == {"nodes": [], "edges": []}


def test_plain_packages_hidden_unless_flagged() -> None:
    from aibom import __version__
    from aibom.inventory import ScanMetadata
    from aibom.models.entities import Package
    from aibom.models.evidence import Evidence
    from aibom.models.findings import Finding, RiskCategory, Severity

    ev = Evidence(file="requirements.txt", line_start=1, line_end=1,
                  snippet="x", matched_pattern="pypi-dependency", confidence=0.9)
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    ai_pkg = inv.add_entity(Package(name="transformers", ecosystem="PyPI", ai=True,
                                    source_evidence=[ev]))
    plain = inv.add_entity(Package(name="flask", ecosystem="PyPI", source_evidence=[ev]))
    vuln_plain = inv.add_entity(Package(name="requests", ecosystem="PyPI",
                                        source_evidence=[ev]))

    finding = Finding(rule_id="OSV-X", title="t", severity=Severity.HIGH,
                      category=RiskCategory.INTEGRITY, description="d", remediation="r",
                      entity_id=vuln_plain.id, entity_name=vuln_plain.name,
                      source_evidence=[ev])
    ids = {n["id"] for n in build_graph(inv, [finding])["nodes"]}
    assert ai_pkg.id in ids          # AI package always shown
    assert vuln_plain.id in ids      # plain dep with a finding shown
    assert plain.id not in ids       # healthy plain dep left to the inventory table
