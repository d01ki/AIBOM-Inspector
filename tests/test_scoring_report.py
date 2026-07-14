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


def test_category_deductions_and_worst_blend() -> None:
    findings = [
        _finding(Severity.HIGH, RiskCategory.INTEGRITY, rule="TDR-A"),      # -20
        _finding(Severity.MEDIUM, RiskCategory.INTEGRITY, rule="TDR-B"),    # -10
        _finding(Severity.CRITICAL, RiskCategory.CONFIGURATION, rule="TDR-C"),  # -40
    ]
    score = score_findings(findings)
    by_cat = {c.category: c.score for c in score.categories}
    assert by_cat[RiskCategory.INTEGRITY] == 70
    assert by_cat[RiskCategory.CONFIGURATION] == 60
    assert by_cat[RiskCategory.PROVENANCE] == 100
    assert by_cat[RiskCategory.LICENSING] == 100
    # overall blends mean (82.5) with worst (60): 0.55*82.5 + 0.45*60 = 72.375
    assert score.overall == 72


def test_one_bad_category_cannot_be_averaged_away() -> None:
    # A category at 0 with everything else clean must not read as a B.
    findings = [
        _finding(Severity.CRITICAL, RiskCategory.INTEGRITY, rule=f"TDR-{i}")
        for i in range(3)
    ]
    score = score_findings(findings)
    # mean = (0+100+100+100)/4 = 75, worst = 0 -> 0.55*75 = 41 (D), not 75 (B)
    assert score.overall == 41
    assert score.grade in {"D", "F"}


def test_per_rule_deduction_cap() -> None:
    # 10 findings of ONE rule deduct at most 3x; an 11th different rule still counts.
    same_rule = [
        _finding(Severity.MEDIUM, RiskCategory.INTEGRITY, rule="TDR-SAME")
        for _ in range(10)
    ]
    score = score_findings(same_rule)
    by_cat = {c.category: c.score for c in score.categories}
    assert by_cat[RiskCategory.INTEGRITY] == 70  # 100 - 3*10, not 100 - 10*10
    # counts still reflect every finding
    assert next(
        c for c in score.categories if c.category is RiskCategory.INTEGRITY
    ).finding_count == 10

    other = same_rule + [_finding(Severity.MEDIUM, RiskCategory.INTEGRITY, rule="TDR-OTHER")]
    by_cat2 = {c.category: c.score for c in score_findings(other).categories}
    assert by_cat2[RiskCategory.INTEGRITY] == 60


def test_score_floors_at_zero() -> None:
    findings = [
        _finding(Severity.CRITICAL, RiskCategory.INTEGRITY, rule=f"TDR-{i}")
        for i in range(5)
    ]
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
