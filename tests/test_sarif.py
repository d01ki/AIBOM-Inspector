"""SARIF 2.1.0 export tests.

The SARIF log is the CI-facing view of the findings: every finding must appear
as a result with a physical location, rule metadata must be complete enough for
GitHub Code Scanning, and the output must be deterministic.
"""

from __future__ import annotations

import json
from typing import Any

from typer.testing import CliRunner

from aibom.cli import app
from aibom.export.sarif import to_sarif, to_sarif_json
from aibom.models.evidence import Evidence
from aibom.models.findings import Finding, RiskCategory, Severity
from aibom.service import run_scan
from tests.conftest import FIXTURE

runner = CliRunner()


def _finding(rule_id: str = "TDR-001", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Pickle-based weight format",
        severity=severity,
        category=RiskCategory.INTEGRITY,
        description="Loading pickle can execute arbitrary code.",
        remediation="Prefer safetensors.",
        entity_name="model.pkl",
        source_evidence=[
            Evidence(
                file="models\\model.pkl",
                line_start=1,
                line_end=1,
                snippet="model.pkl",
                matched_pattern="weight-file",
            )
        ],
    )


def test_sarif_structure_and_rule_metadata() -> None:
    log = to_sarif([_finding()])
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "AIBOM Inspector"
    rule = driver["rules"][0]
    assert rule["id"] == "TDR-001"
    assert rule["shortDescription"]["text"]
    assert rule["help"]["text"]
    assert rule["properties"]["security-severity"] == "8.0"
    assert "ai-supply-chain" in rule["properties"]["tags"]


def test_sarif_result_points_at_evidence_with_forward_slashes() -> None:
    result = to_sarif([_finding()])["runs"][0]["results"][0]
    assert result["ruleId"] == "TDR-001"
    assert result["level"] == "error"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "models/model.pkl"
    assert loc["region"]["startLine"] == 1
    assert result["partialFingerprints"]["aibomFinding/v1"]


def test_sarif_severity_levels() -> None:
    levels = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    for severity, expected in levels.items():
        log = to_sarif([_finding(severity=severity)])
        assert log["runs"][0]["results"][0]["level"] == expected


def test_sarif_rules_deduplicated_and_indexed() -> None:
    findings = [_finding(), _finding(), _finding(rule_id="TDR-009")]
    run = to_sarif(findings)["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["TDR-001", "TDR-009"]
    assert [r["ruleIndex"] for r in run["results"]] == [0, 0, 1]


def test_sarif_finding_without_evidence_still_has_location() -> None:
    finding = _finding()
    finding.source_evidence = []
    result = to_sarif([finding])["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "."


def test_sarif_is_deterministic() -> None:
    findings = run_scan(FIXTURE).findings
    assert to_sarif_json(findings) == to_sarif_json(findings)


def test_cli_writes_sarif(tmp_path: Any) -> None:
    out = tmp_path / "findings.sarif"
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--sarif", str(out)])
    assert result.exit_code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    results = log["runs"][0]["results"]
    assert results  # the vulnerable fixture must produce findings
    rule_ids = {r["ruleId"] for r in results}
    assert "TDR-001" in rule_ids
