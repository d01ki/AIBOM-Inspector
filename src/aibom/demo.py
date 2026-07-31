"""Locate bundled offline demo projects in source and installed layouts."""

from __future__ import annotations

from pathlib import Path

_TS_MARKER = "app/api/support/route.ts"


def impact_demo_path() -> Path | None:
    """Return the built-in Python prompt-to-tool impact fixture."""
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "impact_demo",
        here.parents[2] / "tests" / "fixtures" / "impact-demo",
    ]
    return _first_project(candidates, "app.py")


def ts_impact_demo_path() -> Path | None:
    """Return the built-in TypeScript prompt-to-tool impact fixture."""
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "impact_demo_ts",
        here.parents[2] / "tests" / "fixtures" / "impact-demo-ts",
    ]
    return _first_project(candidates, _TS_MARKER)


def drift_demo_paths() -> tuple[Path, Path] | None:
    """Return same-components baseline/candidate impact drift fixtures (Python)."""
    return _first_pair(
        [
            ("impact_demo_baseline", "impact_demo"),
            ("impact-demo-baseline", "impact-demo"),
        ],
        "app.py",
    )


def ts_drift_demo_paths() -> tuple[Path, Path] | None:
    """Return the TypeScript baseline/candidate impact drift fixtures."""
    return _first_pair(
        [
            ("impact_demo_ts_baseline", "impact_demo_ts"),
            ("impact-demo-ts-baseline", "impact-demo-ts"),
        ],
        _TS_MARKER,
    )


def _first_pair(names: list[tuple[str, str]], marker: str) -> tuple[Path, Path] | None:
    here = Path(__file__).resolve()
    roots = [here.parent, here.parents[2] / "tests" / "fixtures"]
    for root, (baseline_name, candidate_name) in zip(roots, names, strict=True):
        baseline = root / baseline_name
        candidate = root / candidate_name
        if (baseline / marker).is_file() and (candidate / marker).is_file():
            return baseline, candidate
    return None


def _first_project(candidates: list[Path], marker: str) -> Path | None:
    for candidate in candidates:
        if (candidate / marker).is_file():
            return candidate
    return None
