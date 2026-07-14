"""Pluggable, evidence-backed source detectors."""

from aibom.detectors.base import Detector, ScanContext
from aibom.detectors.registry import DetectorRegistry, default_registry
from aibom.detectors.result import Detection

__all__ = ["Detection", "Detector", "DetectorRegistry", "ScanContext", "default_registry"]
