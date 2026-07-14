"""Risk engine — deterministic, evidence-backed risk findings + scoring.

The engine runs a registry of rules (SPEC §6, TDR-001…010) over an
:class:`~aibom.inventory.Inventory` and produces :class:`~aibom.models.findings.Finding`
objects. Rules are pure and rule-based: given the same inventory they always
produce the same findings. LLM assistance, where added later, is limited to
*explaining* a finding — never to producing or scoring one.
"""

from __future__ import annotations

from aibom.risk.engine import RiskEngine, evaluate
from aibom.risk.scoring import score_findings

__all__ = ["RiskEngine", "evaluate", "score_findings"]
