"""End-to-end CLI tests via Typer's runner.

These exercise the user-facing ``aibom`` command: rendering, the JSON /
CycloneDX / HTML outputs, and the severity exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from aibom import __version__
from aibom.cli import app
from tests.conftest import FIXTURE

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_renders_inventory_and_score() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    assert result.exit_code == 0
    assert "inventory" in result.stdout.lower()
    assert "Security score" in result.stdout
    assert "TDR-001" in result.stdout  # a finding surfaced


def test_scan_missing_target_exits_2() -> None:
    result = runner.invoke(app, ["scan", "/no/such/path/xyz"])
    assert result.exit_code == 2
    assert "does not exist" in result.stdout


def test_scan_quiet_suppresses_tables() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE), "--quiet"])
    assert result.exit_code == 0
    assert "Security score" not in result.stdout


def test_scan_writes_json_inventory(tmp_path: Any) -> None:
    out = tmp_path / "inv.json"
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--output", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["entities"]
    assert data["metadata"]["tool"] == "aibom"


def test_scan_writes_cyclonedx(tmp_path: Any) -> None:
    out = tmp_path / "bom.json"
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--cyclonedx", str(out)])
    assert result.exit_code == 0
    doc = json.loads(out.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"


def test_scan_writes_html_report(tmp_path: Any) -> None:
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--report", str(out)])
    assert result.exit_code == 0
    html = out.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")


def test_fail_on_high_exits_1() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--fail-on", "high"])
    assert result.exit_code == 1


def test_fail_on_critical_exits_0() -> None:
    # the fixture has no critical findings
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--fail-on", "critical"])
    assert result.exit_code == 0


def test_fail_on_invalid_severity_exits_2() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE), "-q", "--fail-on", "bogus"])
    assert result.exit_code == 2
    assert "invalid --fail-on" in result.stdout


def test_min_confidence_filters(tmp_path: Any) -> None:
    out = tmp_path / "inv.json"
    result = runner.invoke(
        app, ["scan", str(FIXTURE), "-q", "--min-confidence", "0.99", "--output", str(out)]
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    for e in data["entities"]:
        assert max(ev["confidence"] for ev in e["source_evidence"]) >= 0.99


def test_empty_scan_reports_no_components(tmp_path: Path) -> None:
    (tmp_path / "readme.txt").write_text("nothing to see here", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No AI components discovered" in result.stdout


def test_disable_detector_option_is_repeatable(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-disabled")\n',
        encoding="utf-8",
    )
    out = tmp_path / "inventory.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--quiet",
            "--disable-detector",
            "python.openai.ast",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert not [entity for entity in data["entities"] if entity["type"] == "model"]


# --- URL targets and guided entry ------------------------------------------


def test_no_target_non_interactive_exits_2() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
    assert "no scan target given" in result.stdout


def test_no_target_interactive_prompts_and_scans(monkeypatch: Any) -> None:
    monkeypatch.setattr("aibom.cli._stdin_is_tty", lambda: True)
    result = runner.invoke(app, ["scan"], input=f"{FIXTURE}\n")
    assert result.exit_code == 0
    assert "What should I scan?" in result.stdout
    assert "Security score" in result.stdout


def test_url_target_disallowed_host_exits_2() -> None:
    result = runner.invoke(app, ["scan", "https://evil.example/owner/repo"])
    assert result.exit_code == 2
    assert "not allowed" in result.stdout


def test_url_target_clones_and_scans(monkeypatch: Any) -> None:
    from contextlib import contextmanager

    @contextmanager
    def fake_clone(url: str, **kwargs: Any):  # noqa: ANN202
        yield FIXTURE

    monkeypatch.setattr("aibom.server.clone.clone_repo", fake_clone)
    url = "https://github.com/owner/repo"
    out_result = runner.invoke(app, ["scan", url])
    assert out_result.exit_code == 0
    assert "Security score" in out_result.stdout


def test_url_target_records_url_as_metadata_target(monkeypatch: Any, tmp_path: Path) -> None:
    from contextlib import contextmanager

    @contextmanager
    def fake_clone(url: str, **kwargs: Any):  # noqa: ANN202
        yield FIXTURE

    monkeypatch.setattr("aibom.server.clone.clone_repo", fake_clone)
    out = tmp_path / "inv.json"
    url = "https://github.com/owner/repo"
    result = runner.invoke(app, ["scan", url, "-q", "--output", str(out)])
    assert result.exit_code == 0
    assert json.loads(out.read_text())["metadata"]["target"] == url
