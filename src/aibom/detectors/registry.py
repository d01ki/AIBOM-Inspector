"""Detector registry with stable IDs and per-detector disabling."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from aibom.detectors.base import Detector, ScanContext
from aibom.detectors.result import Detection


class DetectorRegistry:
    """Ordered registry used by collectors to run compatible detectors."""

    def __init__(
        self,
        detectors: Sequence[Detector] = (),
        *,
        disabled: set[str] | None = None,
    ) -> None:
        self._detectors: list[Detector] = []
        self._disabled = disabled or set()
        for detector in detectors:
            self.register(detector)

    @property
    def detector_ids(self) -> list[str]:
        return [d.detector_id for d in self._detectors if d.detector_id not in self._disabled]

    def register(self, detector: Detector) -> None:
        if any(existing.detector_id == detector.detector_id for existing in self._detectors):
            raise ValueError(f"duplicate detector id: {detector.detector_id}")
        self._detectors.append(detector)

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        for detector in self._detectors:
            if detector.detector_id in self._disabled or not detector.supports(
                context.relative_path
            ):
                continue
            yield from detector.detect(context)


def default_registry(*, disabled: set[str] | None = None) -> DetectorRegistry:
    """Build the built-in registry lazily to avoid import cycles."""
    from aibom.detectors.python.anthropic import AnthropicPythonDetector
    from aibom.detectors.python.huggingface import HuggingFacePythonDetector
    from aibom.detectors.python.openai import OpenAIPythonDetector

    return DetectorRegistry(
        [OpenAIPythonDetector(), AnthropicPythonDetector(), HuggingFacePythonDetector()],
        disabled=disabled,
    )
