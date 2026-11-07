"""scripts/verify.py must never report a check it did not run as PASS.

These tests pin the status policy (PASS / FAIL / BLOCKED / NOT RUN), the change
-> feature mapping, log redaction and the exit-code contract. Two of them run a
real pytest subprocess on a throwaway test file so the junit parsing and skip
handling are exercised end to end, not just mocked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tests.test_feature_map import FEATURES, verify

Check = verify.Check
Feature = verify.Feature
RunResult = verify.RunResult


def _feature(**kw: object) -> object:
    base = {"id": "f", "doc": "docs/feature-map/f.md", "paths": ["src/x/**"]}
    base.update(kw)
    return Feature(**base)


# ── pytest classification ────────────────────────────────────────────────────


def test_pytest_pass() -> None:
    assert verify.classify_pytest(RunResult(0, "", 1.0), {"tests": 3, "skipped": 0})[0] == "PASS"


def test_all_skipped_is_not_run() -> None:
    status, reason = verify.classify_pytest(RunResult(0, "", 1.0), {"tests": 2, "skipped": 2})
    assert status == "NOT RUN" and "skipped" in reason


def test_no_tests_collected_is_not_run() -> None:
    assert verify.classify_pytest(RunResult(5, "", 1.0), {})[0] == "NOT RUN"


def test_failures_are_fail() -> None:
    status, reason = verify.classify_pytest(
        RunResult(1, "", 1.0), {"tests": 3, "failures": 1, "errors": 0, "skipped": 0}
    )
    assert status == "FAIL" and "1 failed" in reason


def test_missing_interpreter_or_timeout_is_blocked() -> None:
    assert verify.classify_pytest(RunResult(None, "", 0.0, "timed out"), {})[0] == "BLOCKED"
    assert verify.classify_pytest(RunResult(4, "usage error", 0.1), {})[0] == "BLOCKED"


# ── smoke expectations ───────────────────────────────────────────────────────


def test_smoke_checks_exit_output_and_files(tmp_path: Path) -> None:
    (tmp_path / "made.json").write_text("{}", encoding="utf-8")
    spec = {"name": "s", "cmd": ["x"], "expect_exit": 1, "expect_output": "gate",
            "expect_files": ["{out}/made.json"]}
    status, _, artifacts = verify.evaluate_smoke(spec, RunResult(1, "the gate fired", 0.1),
                                                 tmp_path)
    assert status == "PASS" and artifacts == ["made.json"]


def test_smoke_wrong_exit_missing_file_and_output_all_reported(tmp_path: Path) -> None:
    spec = {"name": "s", "cmd": ["x"], "expect_output": "needle",
            "expect_files": ["{out}/absent.json"]}
    status, reason, _ = verify.evaluate_smoke(spec, RunResult(3, "hay", 0.1), tmp_path)
    assert status == "FAIL"
    assert "exit 3, expected 0" in reason and "needle" in reason and "absent.json" in reason


def test_smoke_that_could_not_start_is_blocked(tmp_path: Path) -> None:
    status, _, _ = verify.evaluate_smoke({"name": "s", "cmd": ["x"]},
                                         RunResult(None, "", 0.0, "not found: x"), tmp_path)
    assert status == "BLOCKED"


def test_run_command_reports_a_missing_binary_as_blocked() -> None:
    result = verify.run_command(["definitely-not-a-real-binary-aibom"], timeout=10)
    assert result.exit_code is None and result.error


# ── runner ───────────────────────────────────────────────────────────────────


def test_ui_disabled_is_not_run_and_deduplicated(tmp_path: Path) -> None:
    runner = verify.Runner(tmp_path, ui=False, timeout=10)
    first = runner.ui_check(_feature(id="a"), "vulnerable-ai-app")
    again = runner.ui_check(_feature(id="b"), "vulnerable-ai-app")
    assert first.status == "NOT RUN" and again is first
    assert first.features == ["a", "b"]


def test_manual_items_are_always_not_run(tmp_path: Path) -> None:
    runner = verify.Runner(tmp_path, ui=True, timeout=10)
    assert runner.manual(_feature(), "look at it").status == "NOT RUN"


def test_gate_with_missing_tool_is_blocked(tmp_path: Path) -> None:
    runner = verify.Runner(tmp_path, ui=True, timeout=10)
    check = runner.gate("ghost", ["definitely-not-a-real-binary-aibom"])
    assert check.status == "BLOCKED"
    assert (tmp_path / check.log).is_file()


def test_missing_listed_test_file_fails(tmp_path: Path) -> None:
    runner = verify.Runner(tmp_path, ui=True, timeout=10)
    checks = runner.tests(_feature(tests=["tests/does_not_exist.py"]))
    assert [c.status for c in checks] == ["FAIL"]


def test_real_pytest_run_separates_skips_from_passes(tmp_path: Path) -> None:
    case = tmp_path / "case_pass_skip.py"
    case.write_text(
        "import pytest\n"
        "def test_ok():\n    assert True\n"
        "@pytest.mark.skip(reason='needs a browser')\n"
        "def test_skipped():\n    pass\n",
        encoding="utf-8",
    )
    runner = verify.Runner(tmp_path / "out", ui=True, timeout=120)
    checks = runner.tests(_feature(tests=[case.as_posix()]))
    statuses = {c.kind: c.status for c in checks}
    assert statuses == {"tests": "PASS", "skipped-tests": "NOT RUN"}
    skipped = next(c for c in checks if c.kind == "skipped-tests")
    assert "needs a browser" in skipped.reason
    summary = verify.feature_summary(_feature(), checks)
    assert summary["status"] == "PASS" and summary["not_run"]


def test_real_pytest_failure_is_fail_and_each_file_runs_once(tmp_path: Path) -> None:
    case = tmp_path / "case_fail.py"
    case.write_text("def test_bad():\n    assert 1 == 2\n", encoding="utf-8")
    runner = verify.Runner(tmp_path / "out", ui=True, timeout=120)
    first = runner.tests(_feature(id="a", tests=[case.as_posix()]))
    second = runner.tests(_feature(id="b", tests=[case.as_posix()]))
    assert [c.status for c in first] == ["FAIL"] and second == []
    assert first[0].features == ["a", "b"]
    assert verify.exit_code(runner.checks) == 1


# ── policy ───────────────────────────────────────────────────────────────────


def test_exit_code_policy() -> None:
    def c(status: str) -> object:
        return Check("x", "tests", "x", status, ["f"])

    assert verify.exit_code([c("PASS"), c("NOT RUN")]) == 0
    assert verify.exit_code([c("PASS"), c("BLOCKED")]) == 2
    assert verify.exit_code([c("BLOCKED"), c("FAIL")]) == 1


def test_feature_with_only_manual_checks_is_not_pass() -> None:
    manual = Check("m", "manual", "m", "NOT RUN", ["f"])
    assert verify.feature_summary(_feature(), [manual])["status"] == "NOT RUN"


def test_feature_with_a_blocked_check_is_not_pass() -> None:
    checks = [Check("t", "tests", "t", "PASS", ["f"]), Check("u", "ui", "u", "BLOCKED", ["f"])]
    assert verify.feature_summary(_feature(), checks)["status"] == "BLOCKED"


def test_redaction_removes_credentials() -> None:
    # Obviously fake values, assembled at run time so that secret scanners do
    # not mistake this test's source for a leaked credential.
    fake = "abcdefghijklmnopqrstuvwx"
    bearer, ghp, akia, hf = "Bear" + "er", "gh" + "p_", "AK" + "IA", "h" + "f_"
    raw = (
        f"OPENAI_API_KEY=sk-proj-{fake}\n"
        f"Authorization: {bearer} {fake}yz123\n"
        f"token: {ghp}{fake}yz0123\n"
        f"aws {akia}ABCDEFGHIJKLMNOP and {hf}{fake}yz\n"
    )
    out = verify.redact(raw)
    for secret in ("abcdefghijklmnopqrstuvwx", "AKIAABCDEFGHIJKLMNOP", "ghp_", "hf_abc"):
        assert secret not in out
    assert out.count("[REDACTED]") >= 4


# ── mapping ──────────────────────────────────────────────────────────────────


def test_mapping_includes_feature_docs_and_tests() -> None:
    hit, unmapped = verify.map_files(
        ["docs/feature-map/drift.md", "tests/test_osv.py", "notes.txt"], FEATURES
    )
    assert {f.id for f in hit} >= {"drift", "enrichment", "verification"}
    assert unmapped == ["notes.txt"]


def test_list_mode_prints_mapping(capsys: object) -> None:
    code = verify.main(["--list", "--files", "src/aibom/linking.py"])
    out = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert code == 0 and out["features"] == ["dependency-map"]


def test_report_markdown_lists_every_check() -> None:
    check = Check("smoke-01", "smoke", "f: s", "FAIL", ["f"], "exit 3, expected 0",
                  ["x"], 3, 0, 0.1, "logs/smoke-01.log")
    report = {
        "context": {"commit": "abc", "branch": "b", "dirty": False, "base": "main",
                    "python": sys.version.split()[0], "platform": "p"},
        "mode": "files", "started": "now", "exit_code": 1,
        "totals": dict.fromkeys(verify.STATUSES, 0) | {"FAIL": 1},
        "features": [verify.feature_summary(_feature(), [check])],
        "checks": [verify.asdict(check)], "unmapped": ["notes.txt"],
    }
    md = verify.render_markdown(report)
    assert "| smoke-01 | FAIL |" in md and "3 (want 0)" in md and "`notes.txt`" in md
