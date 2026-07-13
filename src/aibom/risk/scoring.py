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

from aibom.models.findings import (
    CategoryScore,
    Finding,
    RiskCategory,
    SecurityScore,
    Severity,
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
