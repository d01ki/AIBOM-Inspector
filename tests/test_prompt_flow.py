"""Prompt source-to-sink detection and AIBOM-PROMPT-004 tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom.export.cyclonedx import to_cyclonedx
from aibom.models.entities import EntityType, Prompt, RelationshipType
from aibom.models.findings import Severity
from aibom.report.html import render_html
from aibom.service import run_scan


def _scan(
    tmp_path: Path,
    code: str,
    *,
    disabled: set[str] | None = None,
) -> Any:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return run_scan(tmp_path, disabled_detectors=disabled)


def _prompts(result: Any) -> list[Prompt]:
    return [
        entity
        for entity in result.inventory.by_type(EntityType.PROMPT)
        if isinstance(entity, Prompt)
    ]


def test_assistant_instructions_are_an_invoked_prompt_without_content_leak(
    tmp_path: Path,
) -> None:
    secret_instruction = "Internal instruction that must not be serialized"
    result = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "client.beta.assistants.create(\n"
        f'    instructions="{secret_instruction}",\n'
        '    model="gpt-4.1",\n'
        ")\n",
    )

    prompt = next(
        item
        for item in _prompts(result)
        if item.name == "assistant-instructions@app.py:3"
    )
    assert prompt.kind == "system"
    assert prompt.content_hash
    assert prompt.user_controlled is False
    assert prompt.usage.invoked is True
    assert {item.kind for item in prompt.source_evidence} == {"sink"}
    assert secret_instruction not in prompt.model_dump_json()

    model = next(
        entity
        for entity in result.inventory.entities
        if entity.type is EntityType.MODEL and entity.name == "gpt-4.1"
    )
    assert any(
        relationship.source_id == prompt.id
        and relationship.target_id == model.id
        and relationship.relationship is RelationshipType.FLOWS_TO
        for relationship in result.inventory.relationships
    )


def test_http_input_to_system_prompt_emits_flow_and_high_risk_finding(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from fastapi import FastAPI\n"
        "from openai import OpenAI\n"
        "app = FastAPI()\n"
        "client = OpenAI()\n"
        'BASE_PROMPT = "Follow policy. "\n'
        "@app.post('/chat')\n"
        "def chat(request):\n"
        "    system_prompt = BASE_PROMPT + request.user_input\n"
        '    return client.responses.create(model="gpt-4.1", input=system_prompt)\n',
    )

    prompt = next(
        item
        for item in _prompts(result)
        if item.sink_kind == "openai.responses.create.input"
    )
    assert prompt.kind == "system"
    assert prompt.source_kind == "http_request"
    assert prompt.trust_boundary == "network_to_application"
    assert prompt.user_controlled is True
    operations = [step.operation for step in prompt.data_flow_path]
    assert operations[0] == "source:http_request"
    assert operations[-1] == "prompt_sink"
    assert operations.count("variable_reference") == 2
    assert {item.kind for item in prompt.source_evidence} == {"source", "sink"}

    finding = next(item for item in result.findings if item.rule_id == "AIBOM-PROMPT-004")
    assert finding.severity is Severity.HIGH
    assert finding.source_kind == "http_request"
    assert finding.sink_kind == "openai.responses.create.input"
    assert finding.data_flow_path
    html = render_html(result.inventory, result.findings, result.score)
    assert "Flow: http_request &rarr; openai.responses.create.input" in html


def test_tainted_user_message_does_not_taint_static_system_message(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from fastapi import FastAPI\n"
        "from openai import OpenAI\n"
        "app = FastAPI()\n"
        "client = OpenAI()\n"
        "@app.post('/chat')\n"
        "def chat(message):\n"
        "    return client.chat.completions.create(\n"
        '        model="gpt-4.1",\n'
        "        messages=[\n"
        '            {"role": "system", "content": "Stay concise."},\n'
        '            {"role": "user", "content": message},\n'
        "        ],\n"
        "    )\n",
    )

    system = next(item for item in _prompts(result) if item.kind == "system")
    user = next(item for item in _prompts(result) if item.kind == "user")
    assert system.user_controlled is False
    assert user.user_controlled is True
    assert not any(item.rule_id == "AIBOM-PROMPT-004" for item in result.findings)


def test_tainted_system_message_is_flagged(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from flask import Flask, request\n"
        "from openai import OpenAI\n"
        "app = Flask(__name__)\n"
        "client = OpenAI()\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    messages = [\n"
        '        {"role": "system", "content": "Rules: " + request.json["rules"]},\n'
        "    ]\n"
        '    return client.chat.completions.create(model="gpt-4.1", messages=messages)\n',
    )

    system = next(item for item in _prompts(result) if item.kind == "system")
    assert system.user_controlled is True
    assert system.source_kind == "http_request"
    assert any(item.rule_id == "AIBOM-PROMPT-004" for item in result.findings)


def test_environment_source_is_reported_as_unknown_trust_not_untrusted(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import os\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "system_prompt = os.getenv('SYSTEM_PROMPT')\n"
        "client.messages.create(\n"
        '    model="claude-sonnet-4", max_tokens=64, system=system_prompt, messages=[]\n'
        ")\n",
    )

    prompt = next(
        item
        for item in _prompts(result)
        if item.sink_kind == "anthropic.messages.system"
    )
    assert prompt.source_kind == "environment"
    assert prompt.user_controlled is None
    assert prompt.content_hash is None
    assert not any(item.rule_id == "AIBOM-PROMPT-004" for item in result.findings)


def test_prompt_flow_properties_are_exported_to_cyclonedx(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-4.1", instructions="Be helpful")\n',
    )
    document = to_cyclonedx(result.inventory)
    component = next(
        item
        for item in document["components"]
        if item["name"].startswith("system-prompt@app.py")
    )
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties["aibom:prompt_sink_kind"] == "openai.responses.create.instructions"
    assert properties["aibom:prompt_user_controlled"] == "false"
    assert properties["aibom:prompt_model_refs"] == "gpt-4.1"
    assert "aibom:prompt_flow_step" in properties


def test_unrelated_create_call_and_disabled_detector_do_not_emit_prompt(tmp_path: Path) -> None:
    unrelated = _scan(tmp_path, "client.responses.create(input='hello')\n")
    assert not _prompts(unrelated)

    disabled_path = tmp_path / "disabled"
    disabled_path.mkdir()
    disabled = _scan(
        disabled_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-4.1", instructions="Be helpful")\n',
        disabled={"python.prompt-flow.ast", "legacy.regex"},
    )
    assert not _prompts(disabled)
