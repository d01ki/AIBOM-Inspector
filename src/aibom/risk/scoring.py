"""Security scoring — a reproducible 0–100 aggregate over the four categories.

Formula (also surfaced in the report and web UI):

1. Each category starts at 100 and loses ``severity.deduction`` points per
   finding in that category (critical 40 / high 20 / medium 10 / low 3),
   floored at 0. At most :data:`PER_RULE_CAP` findings of the *same rule*
   count toward the deduction, so one repeated smell (e.g. fifty unpinned
   references) cannot zero a category by itself.
2. The overall score blends the category mean with the worst category:
   ``overall = 0.55 * mean + 0.45 * worst``. A single wrecked category
   therefore drags the overall down instead of being averaged away — a repo
   with pickle weights and code execution risks can no longer coast to an A
   on the strength of the categories it simply has no components in.

The score is a pure function of the deterministic findings — never
LLM-derived (SPEC §6).
"""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel

from aibom.models.findings import (
    CategoryScore,
    Finding,
    RiskCategory,
    SecurityScore,
    Severity,
)


class Headline(BaseModel):
    """The first thing a reader sees: what to do, decided by the worst finding.

    The hygiene score is a secondary detail. A critical finding is "action
    required" whatever the score says, so a 76/B can never read as a pass.
    """

    status: str  # action_required | review | no_findings
    label: str
    detail: str
    critical: int
    high: int
    medium: int
    low: int


def headline(findings: list[Finding]) -> Headline:
    counts = Counter(f.severity for f in findings)
    crit, high = counts[Severity.CRITICAL], counts[Severity.HIGH]
    med, low = counts[Severity.MEDIUM], counts[Severity.LOW]
    if crit or high:
        parts = [f"{n} {word}" for n, word in ((crit, "critical"), (high, "high")) if n]
        return Headline(
            status="action_required", label="Action required",
            detail=" and ".join(parts) + " finding(s) to fix before relying on this code.",
            critical=crit, high=high, medium=med, low=low,
        )
    if med or low:
        parts = [f"{n} {word}" for n, word in ((med, "medium"), (low, "low")) if n]
        return Headline(
            status="review", label="Review",
            detail=" and ".join(parts) + " finding(s); no critical or high finding.",
            critical=0, high=0, medium=med, low=low,
        )
    return Headline(
        status="no_findings", label="No findings from the applied rules",
        detail="None of the rules matched in the analyzed scope. This is not a proof "
        "that the repository is safe; see the coverage notes.",
        critical=0, high=0, medium=0, low=0,
    )

#: Max findings of one rule that count toward a category's deduction.
PER_RULE_CAP = 3

#: Blend weights for the overall score.
_MEAN_WEIGHT = 0.55
_WORST_WEIGHT = 0.45


def score_findings(findings: list[Finding]) -> SecurityScore:
    per_category: dict[RiskCategory, int] = dict.fromkeys(RiskCategory, 100)
    counts: dict[RiskCategory, int] = dict.fromkeys(RiskCategory, 0)
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    deducted: Counter[str] = Counter()

    for f in findings:
        counts[f.category] += 1
        severity_counts[f.severity.value] += 1
        deducted[f.rule_id] += 1
        if deducted[f.rule_id] > PER_RULE_CAP:
            continue  # repeated instances of one smell stop compounding
        per_category[f.category] = max(0, per_category[f.category] - f.severity.deduction)

    categories = [
        CategoryScore(category=c, score=per_category[c], finding_count=counts[c])
        for c in RiskCategory
    ]
    mean = sum(per_category.values()) / len(per_category)
    worst = min(per_category.values())
    overall = round(_MEAN_WEIGHT * mean + _WORST_WEIGHT * worst)
    return SecurityScore(
        overall=overall, categories=categories, severity_counts=severity_counts
    )
