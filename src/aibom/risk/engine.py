"""The risk engine — run the rule registry and order the findings."""

from __future__ import annotations

from aibom.inventory import Inventory
from aibom.models.findings import Finding
from aibom.risk.rules import ALL_RULES, Rule


class RiskEngine:
    """Evaluate a set of deterministic rules against an inventory."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else list(ALL_RULES)

    def evaluate(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule(inventory))
        return _order(findings)


def evaluate(inventory: Inventory) -> list[Finding]:
    """Convenience: evaluate the default rule set."""
    return RiskEngine().evaluate(inventory)


def order_findings(findings: list[Finding]) -> list[Finding]:
    """Sort most-severe first, then by rule id and entity for stable output."""
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.rule_id, f.entity_name or "", f.title),
    )


# Backwards-compatible alias.
_order = order_findings
