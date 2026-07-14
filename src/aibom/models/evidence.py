"""Evidence — the trust contract of the tool.

Every entity and every finding must carry at least one piece of evidence that
points back to a concrete location in the scanned source. No evidence, no claim.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """A single, verifiable observation extracted from scanned source.

    An Evidence pins a claim to a file, a line span, and the exact pattern that
    matched, so a human (or CI) can audit every entity the scanner reports.
    """

    file: str = Field(description="Repo-relative path of the file the match came from.")
    line_start: int = Field(ge=1, description="1-indexed first line of the match.")
    line_end: int = Field(ge=1, description="1-indexed last line of the match.")
    column_start: int | None = Field(
        default=None, ge=1, description="Optional 1-indexed first column of the match."
    )
    column_end: int | None = Field(
        default=None, ge=1, description="Optional 1-indexed last column of the match."
    )
    snippet: str = Field(description="The matched source text (trimmed).")
    matched_pattern: str = Field(
        description="Identifier of the detector/pattern that produced this evidence."
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Detector confidence that this observation is a true positive.",
    )
    detector_id: str | None = Field(
        default=None, description="Stable identifier of the detector that produced this evidence."
    )
    kind: str = Field(default="source", description="Evidence kind, e.g. AST, regex, or manifest.")

    def location(self) -> str:
        """Return a clickable-style `path:line` reference."""
        if self.line_start == self.line_end:
            return f"{self.file}:{self.line_start}"
        return f"{self.file}:{self.line_start}-{self.line_end}"
