"""Trust-boundary exposure path synthesis."""

from __future__ import annotations

from pathlib import Path

from aibom.exposure import build_exposure_paths
from aibom.report.html import render_html
from aibom.service import run_scan


def test_privileged_exposure_path_links_source_sink_and_model(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "from openai import OpenAI\n"
        "app = FastAPI()\n"
        "client = OpenAI()\n"
        'POLICY = "private policy wording"\n'
        "@app.post('/chat')\n"
        "def chat(message):\n"
        "    system_prompt = POLICY + message\n"
        '    return client.responses.create(model="gpt-4.1", instructions=system_prompt)\n',
        encoding="utf-8",
    )

    result = run_scan(tmp_path)
    paths = build_exposure_paths(result.inventory)
    path = next(item for item in paths if item.privileged)

    assert path.source_kind == "http_parameter"
    assert path.sink_kind == "openai.responses.create.instructions"
    assert path.trust_boundary == "network_to_application"
    assert path.model_names == ["gpt-4.1"]
    assert path.prompt_anchor.startswith("prompt-slot:")
    assert [step.operation for step in path.data_flow_path][-1] == "prompt_sink"
    assert "private policy wording" not in path.model_dump_json()

    html = render_html(result.inventory, result.findings, result.score)
    assert "Privileged prompt exposure" in html
    assert "http_parameter &rarr; openai.responses.create.instructions" in html
    assert "private policy wording" not in html


def test_static_privileged_prompt_is_not_an_exposure_path(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-4.1", instructions="private policy wording")\n',
        encoding="utf-8",
    )

    result = run_scan(tmp_path)
    assert not build_exposure_paths(result.inventory)


def test_legacy_system_prompt_evidence_keeps_only_a_hash(tmp_path: Path) -> None:
    private_text = "private policy wording that must not leave the source file"
    (tmp_path / "app.py").write_text(
        f'SYSTEM_PROMPT = "{private_text}"\n',
        encoding="utf-8",
    )

    result = run_scan(tmp_path)
    dumped = result.inventory.model_dump_json()
    assert private_text not in dumped
    assert "<prompt content sha256:" in dumped
