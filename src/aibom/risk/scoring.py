"""Security scoring — a reproducible 0–100 aggregate over the four categories.

Formula (also surfaced in the HTML report):
each category starts at 100 and loses ``severity.deduction`` points for every
finding in that category, floored at 0. The overall score is the mean of the
four category scores, rounded to the nearest integer. The score is a pure
function of the deterministic findings — never LLM-derived (SPEC §6).
"""

from __future__ import annotations

from aibom.models.findings import (
    CategoryScore,
    Finding,
    RiskCategory,
    SecurityScore,
    Severity,
)


def score_findings(findings: list[Finding]) -> SecurityScore:
    per_category: dict[RiskCategory, int] = dict.fromkeys(RiskCategory, 100)
    counts: dict[RiskCategory, int] = dict.fromkeys(RiskCategory, 0)
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}

    for f in findings:
        per_category[f.category] = max(0, per_category[f.category] - f.severity.deduction)
        counts[f.category] += 1
        severity_counts[f.severity.value] += 1

    categories = [
        CategoryScore(category=c, score=per_category[c], finding_count=counts[c])
        for c in RiskCategory
    ]
    overall = round(sum(per_category.values()) / len(per_category))
    return SecurityScore(
        overall=overall, categories=categories, severity_counts=severity_counts
    )
