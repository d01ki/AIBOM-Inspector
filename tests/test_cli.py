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


# --- guided menu and demo ---------------------------------------------------


def test_bare_invocation_non_tty_prints_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "guided menu" in result.stdout


def test_menu_demo_scan(monkeypatch: Any) -> None:
    monkeypatch.setattr("aibom.cli._stdin_is_tty", lambda: True)
    result = runner.invoke(app, [], input="1\n")
    assert result.exit_code == 0
    assert "Bundled sample app" in result.stdout
    assert "Untrusted input reaching a bound tool" in result.stdout
    assert "Security score" in result.stdout
    assert "AIBOM-IMPACT-001" in result.stdout


def test_menu_quit(monkeypatch: Any) -> None:
    monkeypatch.setattr("aibom.cli._stdin_is_tty", lambda: True)
    result = runner.invoke(app, [], input="q\n")
    assert result.exit_code == 0
    assert "Security score" not in result.stdout


def test_menu_invalid_choice_reprompts(monkeypatch: Any) -> None:
    monkeypatch.setattr("aibom.cli._stdin_is_tty", lambda: True)
    result = runner.invoke(app, [], input="9\nq\n")
    assert result.exit_code == 0
    assert "Please answer" in result.stdout


def test_scan_demo_flag() -> None:
    result = runner.invoke(app, ["scan", "--demo"])
    assert result.exit_code == 0
    assert "TDR-001" in result.stdout


def test_demo_command_runs_impact_and_drift() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "Untrusted input reaching a bound tool" in result.stdout
    assert "Behavioral drift demo" in result.stdout
    assert "impact_path_added" in result.stdout


def test_scan_target_under_ignored_dir_name_still_scans(tmp_path: Path) -> None:
    # A target living *inside* a directory named like an ignored dir (venv,
    # site-packages, ...) must still be scanned; only subdirs inside the target
    # are subject to ignore rules. This is how the wheel-bundled demo app ships.
    nested = tmp_path / "site-packages" / "aibom" / "demo_app"
    nested.mkdir(parents=True)
    (nested / "app.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-4o-mini")\n',
        encoding="utf-8",
    )
    (nested / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    out = tmp_path / "inv.json"
    result = runner.invoke(app, ["scan", str(nested), "-q", "--output", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["stats"]["files_scanned"] == 2
    names = {e["name"] for e in data["entities"]}
    assert "gpt-4o-mini" in names


# ── CISA 2026 SBOM minimum elements ──────────────────────────────────────────


def test_scan_prints_minimum_elements_summary() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    assert result.exit_code == 0
    assert "CISA 2026 SBOM minimum elements" in result.stdout


def test_scan_writes_minimum_elements_report(tmp_path: Path) -> None:
    out = tmp_path / "elements.json"
    result = runner.invoke(
        app, ["scan", str(FIXTURE), "-q", "--minimum-elements", str(out)]
    )
    assert result.exit_code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["conformant"] is True
    assert report["summary"]["missing"] == 0
    assert {e["id"] for e in report["elements"]} >= {
        "sbom-author",
        "component-hash",
        "component-hash-algorithm",
        "component-license",
        "sbom-generation-context",
        "coverage",
        "known-unknowns",
    }


def test_sbom_author_and_lifecycle_reach_the_bom(tmp_path: Path) -> None:
    out = tmp_path / "bom.json"
    result = runner.invoke(
        app,
        [
            "scan", str(FIXTURE), "-q",
            "--sbom-author", "Acme Security",
            "--sbom-supplier", "Acme Inc",
            "--sbom-lifecycle", "build",
            "--cyclonedx", str(out),
        ],
    )
    assert result.exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["metadata"]["authors"] == [{"name": "Acme Security"}]
    assert doc["metadata"]["supplier"] == {"name": "Acme Inc"}
    assert doc["metadata"]["lifecycles"] == [{"phase": "build"}]


def test_invalid_lifecycle_exits_2() -> None:
    result = runner.invoke(
        app, ["scan", str(FIXTURE), "-q", "--sbom-lifecycle", "whenever"]
    )
    assert result.exit_code == 2
    assert "invalid --sbom-lifecycle" in result.stdout


def test_conformance_command_checks_an_existing_bom(tmp_path: Path) -> None:
    bom = tmp_path / "bom.json"
    assert runner.invoke(app, ["scan", str(FIXTURE), "-q", "--cyclonedx", str(bom)]).exit_code == 0
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["conformance", str(bom), "-o", str(out), "--fail-on-missing"])
    assert result.exit_code == 0
    assert "Minimum elements" in result.stdout
    assert json.loads(out.read_text(encoding="utf-8"))["conformant"] is True


def test_conformance_fails_on_a_bom_with_silent_gaps(tmp_path: Path) -> None:
    bom = tmp_path / "bare.json"
    bom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
                "components": [{"type": "library", "bom-ref": "a", "name": "left-pad"}],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["conformance", str(bom), "--fail-on-missing"])
    assert result.exit_code == 1
    assert "silently missing" in result.stdout


def test_conformance_rejects_a_non_cyclonedx_document(tmp_path: Path) -> None:
    spdx = tmp_path / "spdx.json"
    spdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    result = runner.invoke(app, ["conformance", str(spdx)])
    assert result.exit_code == 2
    assert "not a CycloneDX document" in result.stdout


def test_no_lockfiles_flag_drops_transitive_components(tmp_path: Path) -> None:
    locked = Path(__file__).parent / "fixtures" / "locked-ai-app"
    out = tmp_path / "inv.json"
    result = runner.invoke(
        app, ["scan", str(locked), "-q", "--no-lockfiles", "--output", str(out)]
    )
    assert result.exit_code == 0
    entities = json.loads(out.read_text(encoding="utf-8"))["entities"]
    assert not any(e.get("dependency_scope") == "transitive" for e in entities)
