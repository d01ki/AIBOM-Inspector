"""Risk signals — evidence-bearing scan facts that are not AI entities.

Some risk-relevant observations are not themselves components: a
``trust_remote_code=True`` flag, or a hardcoded secret sitting next to an AI
call. Collectors record these as :class:`RiskSignal`\\s so the risk engine can
reason over them without re-reading source. Every signal still carries evidence.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aibom.models.evidence import Evidence


class RiskSignal(BaseModel):
    """A non-entity, evidence-backed observation relevant to risk rules."""

    kind: str = Field(description="e.g. 'trust_remote_code' | 'hardcoded_secret'.")
    detail: str | None = Field(default=None, description="Optional human-readable context.")
    source_evidence: list[Evidence] = Field(default_factory=list)

    def location_key(self) -> tuple[str, str, int]:
        ev = self.source_evidence[0] if self.source_evidence else None
        return (self.kind, ev.file if ev else "", ev.line_start if ev else 0)
