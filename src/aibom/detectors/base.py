"""Common detector protocol and immutable scan context."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from aibom.detectors.result import Detection
from aibom.models.analysis import SourceContext

if TYPE_CHECKING:
    from collections.abc import Iterable

    from aibom.detectors.python.parser import PythonModule


@dataclass(frozen=True)
class ScanContext:
    """A source file plus any safe, pre-parsed representation of it."""

    root: Path
    path: Path
    relative_path: str
    text: str
    source_context: SourceContext
    python: PythonModule | None = None


class Detector(Protocol):
    """Minimal interface implemented by independently testable detectors."""

    detector_id: str

    def supports(self, path: str) -> bool:
        """Return whether this detector can inspect ``path``."""
        ...

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        """Return evidence-backed detections without executing target code."""
        ...
