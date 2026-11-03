"""The feature map must stay true to the repository.

``docs/feature-map/*.md`` drives which checks ``scripts/verify.py`` runs for a
change. A stale glob silently skips verification, so drift is a test failure:

* every glob matches at least one tracked file;
* every listed test file exists;
* every shipped source file (``src/aibom/**``, ``web/**``) belongs to a feature;
* every feature can be verified somehow (tests, smoke, UI or a manual item);
* every feature file has the sections the conventions require.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]

_SECTIONS = (
    "## Overview",
    "## Entry points",
    "## Source",
    "## Depends on",
    "## Normal paths",
    "## Error paths",
    "## Boundaries",
    "## How to verify",
    "## Expected results",
    "## Evidence",
)


def _load_verify() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_script", ROOT / "scripts" / "verify.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verify = _load_verify()
FEATURES = verify.load_features()


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    return [line for line in out.stdout.splitlines() if (ROOT / line).exists()]


TRACKED = _tracked()


def test_feature_ids_are_unique() -> None:
    ids = [f.id for f in FEATURES]
    assert len(ids) == len(set(ids))


def test_index_lists_every_feature_file() -> None:
    index = (ROOT / "docs" / "feature-map.md").read_text(encoding="utf-8")
    for path in (ROOT / "docs" / "feature-map").glob("*.md"):
        assert f"(feature-map/{path.name})" in index, f"{path.name} missing from the index"


@pytest.mark.parametrize("feature", FEATURES, ids=lambda f: f.id)
def test_every_glob_matches_a_file(feature: object) -> None:
    for pattern in feature.paths:  # type: ignore[attr-defined]
        assert any(verify.matches(p, pattern) for p in TRACKED), f"{pattern!r} matches nothing"


@pytest.mark.parametrize("feature", FEATURES, ids=lambda f: f.id)
def test_listed_tests_exist(feature: object) -> None:
    for test in feature.tests:  # type: ignore[attr-defined]
        assert (ROOT / test).is_file(), f"{test} does not exist"


@pytest.mark.parametrize("feature", FEATURES, ids=lambda f: f.id)
def test_feature_is_verifiable(feature: object) -> None:
    f = feature
    assert f.tests or f.smoke or f.ui or f.manual  # type: ignore[attr-defined]


@pytest.mark.parametrize("feature", FEATURES, ids=lambda f: f.id)
def test_feature_doc_has_required_sections(feature: object) -> None:
    text = (ROOT / feature.doc).read_text(encoding="utf-8")  # type: ignore[attr-defined]
    missing = [s for s in _SECTIONS if s not in text]
    assert not missing, f"{feature.doc} lacks {missing}"  # type: ignore[attr-defined]


@pytest.mark.parametrize("feature", FEATURES, ids=lambda f: f.id)
def test_smoke_specs_are_well_formed(feature: object) -> None:
    for spec in feature.smoke:  # type: ignore[attr-defined]
        assert spec.get("name") and isinstance(spec.get("cmd"), list) and spec["cmd"]
        assert set(spec) <= {"name", "cmd", "expect_exit", "expect_files", "expect_output",
                             "timeout"}, f"unknown smoke keys in {spec['name']}"


def test_every_shipped_source_file_is_mapped() -> None:
    shipped = [p for p in TRACKED if p.startswith(("src/aibom/", "web/")) and
               "__pycache__" not in p]
    unmapped = [
        p for p in shipped
        if not any(verify.matches(p, g) for f in FEATURES for g in f.paths)
    ]
    assert not unmapped, f"add these to a feature in docs/feature-map/: {unmapped}"


def test_ui_fixtures_exist() -> None:
    for feature in FEATURES:
        for fixture in feature.ui:
            assert (ROOT / "tests" / "fixtures" / fixture).is_dir(), fixture
