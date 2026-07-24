"""Config file (aibom.toml / [tool.aibom]) and rule-suppression tests.

The config is an organization's scanning policy: it must be validated loudly,
must lose to explicit CLI flags, and suppression must remove findings from the
score and the --fail-on gate — but only when the *caller* asks, never because
the scanned repo says so (the server never applies target config).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aibom.cli import app
from aibom.config import ConfigError, ScanConfig, ignored, load_config
from aibom.service import run_scan
from tests.conftest import FIXTURE

runner = CliRunner()


# --- loading ---------------------------------------------------------------


def test_defaults_when_no_config(tmp_path: Path) -> None:
    assert load_config(tmp_path) == ScanConfig()


def test_loads_dedicated_aibom_toml(tmp_path: Path) -> None:
    (tmp_path / "aibom.toml").write_text(
        'fail_on = "high"\n'
        "min_confidence = 0.7\n"
        'disable_detectors = ["python.openai.ast"]\n'
        'ignore_rules = ["TDR-004", "OSV-*"]\n',
        encoding="utf-8",
    )
    config = load_config(tmp_path)
    assert config.fail_on is not None and config.fail_on.value == "high"
    assert config.min_confidence == 0.7
    assert config.disable_detectors == ["python.openai.ast"]
    assert config.ignore_rules == ["TDR-004", "OSV-*"]


def test_loads_tool_aibom_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n\n[tool.aibom]\nfail_on = "critical"\n', encoding="utf-8"
    )
    config = load_config(tmp_path)
    assert config.fail_on is not None and config.fail_on.value == "critical"


def test_aibom_toml_wins_over_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[tool.aibom]\nfail_on = "low"\n', encoding="utf-8")
    (tmp_path / "aibom.toml").write_text('fail_on = "high"\n', encoding="utf-8")
    config = load_config(tmp_path)
    assert config.fail_on is not None and config.fail_on.value == "high"


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "aibom.toml").write_text('ignore_rule = ["TDR-004"]\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="ignore_rule"):
        load_config(tmp_path)


def test_invalid_severity_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "aibom.toml").write_text('fail_on = "sky-high"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_broken_toml_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "aibom.toml").write_text("fail_on = [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(tmp_path)


# --- ignore pattern matching ----------------------------------------------


def test_ignored_exact_and_family() -> None:
    assert ignored("TDR-004", ["TDR-004"])
    assert not ignored("TDR-004", ["TDR-001"])
    assert ignored("OSV-GHSA-1234", ["OSV-*"])
    assert not ignored("TDR-001", ["OSV-*"])
    assert not ignored("TDR-001", [])


# --- suppression through the pipeline -------------------------------------


def test_run_scan_suppression_excludes_from_score() -> None:
    baseline = run_scan(FIXTURE)
    suppressed = run_scan(FIXTURE, ignore_rules=["TDR-*", "AIBOM-*"])
    assert baseline.findings
    assert not suppressed.findings
    assert suppressed.score.overall >= baseline.score.overall


# --- CLI integration -------------------------------------------------------


def _fixture_copy(tmp_path: Path) -> Path:
    """A private copy of the vulnerable fixture we can drop config files into."""
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE, target)
    return target


def test_config_fail_on_gates_exit_code(tmp_path: Path) -> None:
    target = _fixture_copy(tmp_path)
    (target / "aibom.toml").write_text('fail_on = "high"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target), "-q"])
    assert result.exit_code == 1


def test_cli_flag_overrides_config_fail_on(tmp_path: Path) -> None:
    target = _fixture_copy(tmp_path)
    (target / "aibom.toml").write_text('fail_on = "high"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target), "-q", "--fail-on", "critical"])
    assert result.exit_code == 0


def test_no_config_ignores_target_policy(tmp_path: Path) -> None:
    target = _fixture_copy(tmp_path)
    (target / "aibom.toml").write_text('fail_on = "high"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target), "-q", "--no-config"])
    assert result.exit_code == 0


def test_ignore_rule_flag_removes_finding(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE), "--ignore-rule", "TDR-001"])
    assert result.exit_code == 0
    assert "TDR-001" not in result.stdout
    result_baseline = runner.invoke(app, ["scan", str(FIXTURE)])
    assert "TDR-001" in result_baseline.stdout


def test_config_ignore_rules_survive_into_sarif(tmp_path: Path) -> None:
    target = _fixture_copy(tmp_path)
    (target / "aibom.toml").write_text('ignore_rules = ["TDR-*", "AIBOM-*"]\n', encoding="utf-8")
    out = tmp_path / "log.sarif"
    result = runner.invoke(app, ["scan", str(target), "-q", "--sarif", str(out)])
    assert result.exit_code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["runs"][0]["results"] == []


def test_invalid_config_exits_2(tmp_path: Path) -> None:
    target = _fixture_copy(tmp_path)
    (target / "aibom.toml").write_text('nope = "x"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target), "-q"])
    assert result.exit_code == 2
    assert "invalid aibom config" in result.stdout
