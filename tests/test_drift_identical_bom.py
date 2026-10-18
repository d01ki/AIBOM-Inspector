"""Identical-BOM trust-boundary drift across files.

"An AIBOM does not change. The attack surface does."  Each test compares two
revisions and pins what the drift report may and may not claim: a component
inventory is only called identical over a stated scope, a new path is Critical
only when proven, an unresolved one is shown but never gates, and moving code
around is not a new attack surface.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aibom.cli import app
from aibom.drift import DriftKind, DriftReport, compare_scan_results
from aibom.service import run_scan

FIXTURES = Path(__file__).parent / "fixtures"
PAIRS = {
    "python": (FIXTURES / "xfile-py-baseline", FIXTURES / "xfile-py-candidate"),
    "typescript": (FIXTURES / "xfile-ts-baseline", FIXTURES / "xfile-ts-candidate"),
}
_PATH_KINDS = {
    DriftKind.IMPACT_PATH_ADDED,
    DriftKind.IMPACT_PATH_REMOVED,
    DriftKind.IMPACT_PATH_CHANGED,
    DriftKind.EXPOSURE_ADDED,
    DriftKind.EXPOSURE_REMOVED,
}


def _diff(baseline: Path, candidate: Path) -> DriftReport:
    return compare_scan_results(run_scan(baseline), run_scan(candidate))


def _kinds(report: DriftReport) -> list[DriftKind]:
    return [change.kind for change in report.changes]


def _copy(source: Path, target: Path) -> Path:
    shutil.copytree(source, target)
    return target


def _edit(root: Path, name: str, old: str, new: str) -> None:
    path = root / name
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{old!r} not in {name}"
    path.write_text(text.replace(old, new), encoding="utf-8")


@pytest.mark.parametrize("language", sorted(PAIRS))
def test_identical_bom_new_cross_file_path_is_added(language: str) -> None:
    report = _diff(*PAIRS[language])

    assert report.bom is not None
    assert report.bom.identical is True
    assert {"model", "package", "service"} <= set(report.bom.compared_types)
    assert report.bom.added == report.bom.removed == report.bom.changed == []
    assert report.security_boundary_changed is True

    [added] = [c for c in report.changes if c.kind is DriftKind.IMPACT_PATH_ADDED]
    assert added.severity.value == "critical"
    assert added.evidence_level == "proven_static"
    assert added.details["cross_file"] is True
    assert added.details["potential_consequence"]
    assert added.details["limitations"]
    roles = [node["role"] for node in added.details["nodes"]]
    assert roles[0] == "source" and roles[-2:] == ["tool", "operation"]
    assert "privileged_prompt" in roles and "model" in roles
    # No component change explains the new path.
    assert not {DriftKind.COMPONENT_ADDED, DriftKind.COMPONENT_CHANGED} & set(_kinds(report))


@pytest.mark.parametrize("language", sorted(PAIRS))
def test_fixing_the_candidate_removes_the_path(language: str) -> None:
    baseline, candidate = PAIRS[language]
    report = _diff(candidate, baseline)
    assert DriftKind.IMPACT_PATH_REMOVED in _kinds(report)
    assert report.security_boundary_changed is False


@pytest.mark.parametrize("language", sorted(PAIRS))
def test_identical_bom_without_semantic_change_has_no_findings(language: str) -> None:
    candidate = PAIRS[language][1]
    report = _diff(candidate, candidate)
    assert report.changes == []
    assert report.bom is not None and report.bom.identical is True


def test_line_shift_rename_and_relocation_are_stable(tmp_path: Path) -> None:
    candidate = PAIRS["python"][1]
    moved = _copy(candidate, tmp_path / "moved")
    # Line shifts.
    _edit(moved, "routes/api.py", '"""HTTP layer', '\n\n\n"""HTTP layer')
    # Harmless rename of the builder.
    _edit(moved, "prompts/builder.py", "def build_instructions(", "def compose_instructions(")
    _edit(moved, "assistant/main.py", "build_instructions", "compose_instructions")
    # Relocation of the agent factory to another file.
    (moved / "assistant" / "main.py").rename(moved / "assistant" / "factory.py")
    _edit(moved, "routes/api.py", "from assistant.main", "from assistant.factory")

    report = _diff(candidate, moved)
    assert not set(_kinds(report)) & _PATH_KINDS, report.changes
    assert report.security_boundary_changed is False


def test_user_message_only_is_not_a_privileged_change(tmp_path: Path) -> None:
    baseline = PAIRS["python"][0]
    user_only = _copy(baseline, tmp_path / "user")
    _edit(
        user_only,
        "assistant/main.py",
        '        model="gpt-4.1",',
        '        model="gpt-4.1",\n        handoff_description=problem,',
    )
    report = _diff(baseline, user_only)
    assert DriftKind.IMPACT_PATH_ADDED not in _kinds(report)
    assert not any(
        change.kind is DriftKind.EXPOSURE_ADDED and change.details.get("privileged")
        for change in report.changes
    )


def test_unbound_tool_makes_no_reachability_claim(tmp_path: Path) -> None:
    baseline = _copy(PAIRS["python"][0], tmp_path / "base")
    candidate = _copy(PAIRS["python"][1], tmp_path / "cand")
    for root in (baseline, candidate):
        _edit(root, "assistant/main.py", "tools=[run_diagnostic],", "tools=[],")
    report = _diff(baseline, candidate)
    assert DriftKind.EXPOSURE_ADDED in _kinds(report)  # the prompt exposure is real
    assert DriftKind.IMPACT_PATH_ADDED not in _kinds(report)  # but no tool claim


def test_unresolved_builder_is_potential_and_capped(tmp_path: Path) -> None:
    baseline = PAIRS["python"][0]
    dynamic = _copy(PAIRS["python"][1], tmp_path / "dynamic")
    _edit(
        dynamic,
        "prompts/builder.py",
        'return POLICY + "\\nReported problem: " + problem',
        'return render(POLICY, problem)\n\n\nrender = getattr(__import__("jinja2"), "x")',
    )
    report = _diff(baseline, dynamic)
    [added] = [c for c in report.changes if c.kind is DriftKind.IMPACT_PATH_ADDED]
    assert added.evidence_level == "potential"
    assert added.severity.value == "high"  # never Critical without a proof
    assert added.details["impact_severity"] == "critical"
    assert any("not resolved" in item for item in added.details["limitations"])


def test_unknown_input_is_reported_but_never_gates(tmp_path: Path) -> None:
    baseline = PAIRS["python"][0]
    unknown = _copy(baseline, tmp_path / "unknown")
    _edit(
        unknown,
        "assistant/main.py",
        "instructions=build_instructions(problem),",
        'instructions=importlib.import_module("prompts.x").POLICY,',
    )
    report = _diff(baseline, unknown)
    [change] = [c for c in report.changes if c.kind is DriftKind.IMPACT_PATH_UNRESOLVED]
    assert change.evidence_level == "unknown"
    assert change.gates is False
    assert DriftKind.IMPACT_PATH_ADDED not in _kinds(report)

    result = CliRunner().invoke(app, ["diff", str(baseline), str(unknown), "--fail-on", "info"])
    gating = [c for c in report.changes if c.gates]
    assert result.exit_code == (1 if gating else 0)


def test_cli_gate_fails_on_proven_critical_drift() -> None:
    baseline, candidate = PAIRS["typescript"]
    result = CliRunner().invoke(
        app, ["diff", str(baseline), str(candidate), "--fail-on", "critical", "-q"]
    )
    assert result.exit_code == 1


def test_different_boms_are_never_called_identical(tmp_path: Path) -> None:
    baseline = PAIRS["python"][0]
    changed = _copy(baseline, tmp_path / "changed")
    _edit(changed, "assistant/main.py", 'model="gpt-4.1"', 'model="gpt-4.1-mini"')
    report = _diff(baseline, changed)
    assert report.bom is not None
    assert report.bom.identical is False
    assert "model:gpt-4.1-mini" in report.bom.added
