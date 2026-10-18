"""Tests for the competitor-comparison harness that do not need the competitors."""

from __future__ import annotations

from benchmark.competitors.compare import (
    DRIFT_PAIRS,
    ROOT,
    _aibom_drift,
    _cell,
    _markdown,
    _relocation_note,
)


def _finding(rule: str, path: str, line: int, *, suppressed: bool = False) -> dict[str, object]:
    return {
        "rule_id": rule,
        "severity": "critical",
        "suppressed": suppressed,
        "location": {"file_path": path, "start_line": line},
    }


def test_same_rule_same_file_is_a_line_shift_artifact() -> None:
    before = {"findings": [_finding("AGENT-034", "route.ts", 25)]}
    new = {"findings": [_finding("AGENT-034", "route.ts", 24)]}

    note = _relocation_note(before, new)

    assert "line-shift artifact" in note
    run = {"flagged": True, "detail": note}
    assert _cell(run) == "flagged (line-shift artifact)"


def test_genuinely_new_rule_is_not_an_artifact() -> None:
    before = {"findings": [_finding("AGENT-034", "route.ts", 25)]}
    new = {"findings": [_finding("AGENT-001", "route.ts", 24)]}

    assert _relocation_note(before, new) == ""
    assert _cell({"flagged": True, "detail": ""}) == "flagged"


def test_mixed_new_findings_are_not_called_an_artifact() -> None:
    before = {"findings": [_finding("AGENT-034", "route.ts", 25)]}
    new = {
        "findings": [
            _finding("AGENT-034", "route.ts", 24),
            _finding("AGENT-001", "tools.ts", 3),
        ]
    }

    note = _relocation_note(before, new)

    assert note.startswith("some new findings")
    assert "line-shift artifact" not in note


def test_suppressed_findings_are_ignored() -> None:
    before = {"findings": [_finding("AGENT-034", "route.ts", 25, suppressed=True)]}
    new = {"findings": [_finding("AGENT-034", "route.ts", 24)]}

    assert _relocation_note(before, new) == ""


def test_drift_pairs_exist() -> None:
    for _, baseline, candidate, _ in DRIFT_PAIRS:
        assert (ROOT / baseline).is_dir(), baseline
        assert (ROOT / candidate).is_dir(), candidate


def test_aibom_flags_cross_file_pair_with_identical_bom() -> None:
    _, baseline, candidate, _ = DRIFT_PAIRS[3]

    run = _aibom_drift(ROOT / baseline, ROOT / candidate)

    assert run.flagged is True
    assert run.detail.startswith("BOM identical")
    assert "impact_path_added" in run.detail


def test_aibom_does_not_flag_identical_revisions() -> None:
    _, baseline, _, _ = DRIFT_PAIRS[3]

    run = _aibom_drift(ROOT / baseline, ROOT / baseline)

    assert run.flagged is False


def test_markdown_labels_refused_and_missing_tools() -> None:
    report = {
        "tools": {"aibom": "this checkout", "agent-audit": "0.20.0", "cisco-aibom": "1.10.0"},
        "gate": "high+",
        "drift": [
            {
                "name": "pair",
                "baseline": "a",
                "candidate": "b",
                "change": "c",
                "runs": [
                    {
                        "tool": "aibom",
                        "flagged": True,
                        "detail": "BOM identical",
                        "baseline_findings": 0,
                        "candidate_findings": 1,
                    }
                ],
            }
        ],
        "negative_controls": [],
        "cisco_aibom_without_llm": "exit 1: Error: --llm-model is required.",
        "not_run_reason": {"cisco-aibom": "refused (LLM required)"},
    }

    text = _markdown(report)

    assert "| pair | c | flagged | not run | refused (LLM required) |" in text
    assert "exit 1: Error: --llm-model is required." in text
