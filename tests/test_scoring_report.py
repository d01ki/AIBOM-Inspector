"""Tests for security scoring and the HTML report."""

from __future__ import annotations

from aibom.inventory import Inventory
from aibom.models.evidence import Evidence
from aibom.models.findings import Finding, RiskCategory, Severity
from aibom.report.html import render_html
from aibom.risk.engine import evaluate
from aibom.risk.scoring import score_findings


def _finding(sev: Severity, cat: RiskCategory, rule: str = "TDR-XXX") -> Finding:
    return Finding(
        rule_id=rule, title="t", severity=sev, category=cat,
        description="d", remediation="r",
        source_evidence=[Evidence(
            file="a.py", line_start=1, line_end=1, snippet="x",
            matched_pattern="p", confidence=0.9,
        )],
    )


def test_clean_scan_scores_100() -> None:
    score = score_findings([])
    assert score.overall == 100
    assert score.grade == "A"
    assert all(c.score == 100 for c in score.categories)


def test_category_deductions() -> None:
    findings = [
        _finding(Severity.HIGH, RiskCategory.INTEGRITY),      # -20
        _finding(Severity.MEDIUM, RiskCategory.INTEGRITY),    # -10
        _finding(Severity.CRITICAL, RiskCategory.CONFIGURATION),  # -40
    ]
    score = score_findings(findings)
    by_cat = {c.category: c.score for c in score.categories}
    assert by_cat[RiskCategory.INTEGRITY] == 70
    assert by_cat[RiskCategory.CONFIGURATION] == 60
    assert by_cat[RiskCategory.PROVENANCE] == 100
    assert by_cat[RiskCategory.LICENSING] == 100
    # mean of 70, 100, 100, 60 = 82.5 -> 82 or 83 (round-half-to-even -> 82)
    assert score.overall == round((70 + 100 + 100 + 60) / 4)


def test_score_floors_at_zero() -> None:
    findings = [_finding(Severity.CRITICAL, RiskCategory.INTEGRITY) for _ in range(5)]
    by_cat = {c.category: c.score for c in score_findings(findings).categories}
    assert by_cat[RiskCategory.INTEGRITY] == 0


def test_severity_counts() -> None:
    findings = [
        _finding(Severity.HIGH, RiskCategory.INTEGRITY),
        _finding(Severity.HIGH, RiskCategory.PROVENANCE),
        _finding(Severity.LOW, RiskCategory.LICENSING),
    ]
    counts = score_findings(findings).severity_counts
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0


def test_html_report_is_self_contained(fixture_inventory: Inventory) -> None:
    findings = evaluate(fixture_inventory)
    score = score_findings(findings)
    html = render_html(fixture_inventory, findings, score)

    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    # no external resource references
    for needle in ("http://", "https://cdn", "src=", "<script"):
        assert needle not in html.lower() or needle == "http://"
    assert "TDR-001" in html
    assert str(score.overall) in html


def test_html_escapes_entity_names() -> None:
    from aibom import __version__
    from aibom.inventory import ScanMetadata
    from aibom.models.entities import Model

    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    inv.add_entity(Model(
        name="<img src=x onerror=alert(1)>", provider="local",
        source_evidence=[Evidence(
            file="a.py", line_start=1, line_end=1, snippet="x",
            matched_pattern="p", confidence=0.9,
        )],
    ))
    html = render_html(inv, [], score_findings([]))
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html
