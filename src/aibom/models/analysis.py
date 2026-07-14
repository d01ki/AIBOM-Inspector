"""Static-analysis metadata shared by detectors and inventory entities.

The scanner deliberately keeps these models small and serializable.  They
describe what was observed without claiming that unresolved or dynamically
dispatched code is safe.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Reachability(str, Enum):
    """Whether a component can be reached from a known production entrypoint."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class SourceContext(str, Enum):
    """Repository area in which evidence was observed."""

    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "example"
    DOCS = "docs"


class ValueResolution(str, Enum):
    """How confidently a detector resolved a referenced value."""

    NOT_APPLICABLE = "not_applicable"
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class UsageState(BaseModel):
    """Lifecycle states kept separate to avoid treating an import as execution."""

    declared: bool = False
    imported: bool = False
    instantiated: bool = False
    invoked: bool = False
    reachable: Reachability = Reachability.UNKNOWN
    runtime_observed: bool = False


class ConfidenceFactors(BaseModel):
    """Auditable factors behind a detector's confidence score."""

    syntax_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    value_resolution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    framework_identification_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reachability_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    runtime_confirmation: float = Field(default=0.0, ge=0.0, le=1.0)


class ResolutionStep(BaseModel):
    """One non-executing step used to resolve a value from source code."""

    file: str
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    symbol: str | None = None
    value: str | None = None
    operation: str
