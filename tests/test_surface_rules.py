"""Tests for the offline surface rules TDR-011 (MCP server) and TDR-012
(unpinned AI package) — the rules that keep real-world repos from scoring a
contentless 100/A."""

from __future__ import annotations

from typing import Any

from aibom import __version__
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import Package, Service
from aibom.models.evidence import Evidence
from aibom.models.findings import RiskCategory, Severity
from aibom.risk.rules import tdr_011_mcp_server_surface, tdr_012_unpinned_package


def _ev() -> Evidence:
    return Evidence(
        file="server.py", line_start=2, line_end=2, snippet="x",
        matched_pattern="mcp-server", confidence=0.85,
    )


def _inv(*entities: Any) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    for e in entities:
        inv.add_entity(e)
    return inv


def test_tdr011_fires_on_mcp_server() -> None:
    svc = Service(name="mcp-server@server.py", kind="mcp", source_evidence=[_ev()])
    findings = tdr_011_mcp_server_surface(_inv(svc))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.LOW
    assert f.category is RiskCategory.CONFIGURATION
    assert f.source_evidence


def test_tdr011_ignores_client_configs_and_apis() -> None:
    cfg = Service(name="mcp-config@claude.json", kind="mcp", source_evidence=[_ev()])
    api = Service(name="openai", kind="api", source_evidence=[_ev()])
    assert not tdr_011_mcp_server_surface(_inv(cfg, api))


def test_tdr012_fires_on_unpinned_ai_package() -> None:
    pkg = Package(name="transformers", ecosystem="PyPI", version=">=4.40",
                  version_pinned=False, ai=True, source_evidence=[_ev()])
    findings = tdr_012_unpinned_package(_inv(pkg))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].category is RiskCategory.INTEGRITY


def test_tdr012_skips_pinned_package() -> None:
    pkg = Package(name="transformers", ecosystem="PyPI", version="4.40.0",
                  version_pinned=True, ai=True, source_evidence=[_ev()])
    assert not tdr_012_unpinned_package(_inv(pkg))


def test_tdr012_skips_plain_dependencies() -> None:
    # The complete BOM catalogues flask, but AI hygiene rules stay AI-scoped.
    pkg = Package(name="flask", ecosystem="PyPI", version=">=3.0",
                  version_pinned=False, ai=False, source_evidence=[_ev()])
    assert not tdr_012_unpinned_package(_inv(pkg))


def test_mcp_repo_no_longer_scores_perfect(tmp_path: Any) -> None:
    """End-to-end: an MCP server repo must produce findings and a sub-100 score."""
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        'mcp = FastMCP("pentest-tools")\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\nfastmcp\n", encoding="utf-8")

    from aibom.service import run_scan

    result = run_scan(tmp_path)
    rule_ids = {f.rule_id for f in result.findings}
    assert {"TDR-011", "TDR-012"} <= rule_ids
    assert result.score.overall < 100
