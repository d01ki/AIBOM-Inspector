"""Run the benchmark harness in CI as a regression gate.

The labeled mini-repos are controlled, so a perfect score is expected; any drop
means a detector regressed. Also asserts the negative repo yields no false
positives.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1] / "benchmark" / "evaluate.py"


def _load_evaluate() -> object:
    if not _BENCH.exists():
        pytest.skip("benchmark harness not present")
    spec = importlib.util.spec_from_file_location("bench_evaluate", _BENCH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses can resolve the module by name.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_benchmark_is_perfect_on_labeled_repos() -> None:
    evaluate = _load_evaluate()
    report = evaluate.evaluate_all()  # type: ignore[attr-defined]
    assert report["evaluated"] >= 5, report["skipped"]
    overall = report["overall"]
    # Controlled labels: any FP/FN is a real regression.
    assert overall["fp"] == 0, report["repositories"]
    assert overall["fn"] == 0, report["repositories"]
    assert overall["f1"] == 1.0


def test_benchmark_exercises_value_resolution() -> None:
    """The suite must actually cover the hard cases, not just easy literals."""
    evaluate = _load_evaluate()
    report = evaluate.evaluate_all()  # type: ignore[attr-defined]
    cats = report["categories"]
    # models resolved via env-default (py + js), datasets via notebook, MCP server.
    assert cats["models"]["tp"] >= 3
    assert cats["mcp"]["tp"] >= 1
    assert cats["ai_packages"]["tp"] >= 6
