"""Behavioral AIBOM drift detects changes a component-only diff misses."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aibom.cli import app
from aibom.drift import DriftKind, compare_scan_results
from aibom.models.entities import EntityType
from aibom.models.findings import Severity
from aibom.service import run_scan

runner = CliRunner()

_BASELINE = """\
from fastapi import FastAPI
from openai import OpenAI
app = FastAPI()
client = OpenAI()
POLICY = "private policy wording"
@app.post("/chat")
def chat(message):
    messages = [
        {"role": "system", "content": POLICY},
        {"role": "user", "content": message},
    ]
    return client.chat.completions.create(model="gpt-4.1", messages=messages)
"""

_CANDIDATE = """\
from fastapi import FastAPI
from openai import OpenAI
app = FastAPI()
client = OpenAI()
POLICY = "private policy wording"
@app.post("/chat")
def chat(message):
    messages = [
        {"role": "system", "content": POLICY + message},
        {"role": "user", "content": message},
    ]
    return client.chat.completions.create(model="gpt-4.1", messages=messages)
"""


def _targets(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / "app.py").write_text(_BASELINE, encoding="utf-8")
    (candidate / "app.py").write_text(_CANDIDATE, encoding="utf-8")
    return baseline, candidate


def test_detects_new_privileged_flow_with_identical_component_set(tmp_path: Path) -> None:
    baseline, candidate = _targets(tmp_path)
    old = run_scan(baseline)
    new = run_scan(candidate)

    old_components = {
        (entity.type, entity.name)
        for entity in old.inventory.entities
        if entity.type is not EntityType.PROMPT
    }
    new_components = {
        (entity.type, entity.name)
        for entity in new.inventory.entities
        if entity.type is not EntityType.PROMPT
    }
    assert old_components == new_components

    report = compare_scan_results(old, new)
    exposure = next(
        change for change in report.changes if change.kind is DriftKind.EXPOSURE_ADDED
    )
    assert exposure.severity is Severity.HIGH
    assert exposure.details["source_kind"] == "http_parameter"
    assert exposure.details["sink_kind"] == "openai.messages.system.content"
    assert exposure.details["models"] == ["gpt-4.1"]
    assert "private policy wording" not in report.model_dump_json()
    assert not [
        change for change in report.changes if change.kind is DriftKind.COMPONENT_ADDED
    ]


def test_cli_diff_json_and_high_severity_gate(tmp_path: Path) -> None:
    baseline, candidate = _targets(tmp_path)
    output = tmp_path / "drift.json"

    result = runner.invoke(
        app,
        [
            "diff",
            str(baseline),
            str(candidate),
            "--output",
            str(output),
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert "AIBOM behavioral drift" in result.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert any(change["kind"] == "exposure_added" for change in data["changes"])
    assert "private policy wording" not in output.read_text(encoding="utf-8")
