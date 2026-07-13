"""Risk findings, severities, and the security score.

A :class:`Finding` is the risk engine's unit of output. Like every claim in the
tool it is **evidence-backed**: it points at the entity and the concrete
`file:line` locations that triggered it, and it is produced by a deterministic,
rule-based check — never by an LLM (LLM assistance is limited to *explaining* an
already-produced finding, per SPEC §6).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from aibom.models.evidence import Evidence


class Severity(str, Enum):
    """Ordered severity levels. Higher = worse."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def deduction(self) -> int:
        """Points subtracted from a category's 0–100 score by one such finding."""
        return _SEVERITY_DEDUCTION[self]


_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}
_SEVERITY_DEDUCTION = {
    Severity.INFO: 0, Severity.LOW: 3, Severity.MEDIUM: 10,
    Severity.HIGH: 20, Severity.CRITICAL: 40,
}


class RiskCategory(str, Enum):
    """The four scoring categories aggregated into the security score."""

    INTEGRITY = "integrity"
    PROVENANCE = "provenance"
    LICENSING = "licensing"
    CONFIGURATION = "configuration"


class Finding(BaseModel):
    """A single deterministic, evidence-backed risk finding."""

    rule_id: str = Field(description="Stable rule identifier, e.g. 'TDR-001'.")
    title: str
    severity: Severity
    category: RiskCategory
    description: str
    remediation: str
    entity_id: str | None = Field(
        default=None, description="Inventory id of the entity this finding is about, if any."
    )
    entity_name: str | None = None
    source_evidence: list[Evidence] = Field(default_factory=list)


class CategoryScore(BaseModel):
    """Per-category 0–100 score and the findings that shaped it."""

    category: RiskCategory
    score: int
    finding_count: int


class SecurityScore(BaseModel):
    """Weighted aggregate security score (0–100) plus its breakdown.

    Formula (documented here, in the report, and in the web UI for
    reproducibility): each category starts at 100 and loses
    ``severity.deduction`` points per finding (critical 40 / high 20 /
    medium 10 / low 3), floored at 0, counting at most 3 findings per rule.
    The overall score blends the mean with the worst category
    (``0.55 * mean + 0.45 * worst``) so one wrecked category cannot be
    averaged away.
    """

    overall: int
    categories: list[CategoryScore]
    severity_counts: dict[str, int]

    @property
    def grade(self) -> str:
        for cutoff, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
            if self.overall >= cutoff:
                return letter
        return "F"
