"""Strong-link agent blast-radius analysis tests."""

from __future__ import annotations

from pathlib import Path

from aibom.demo import drift_demo_paths
from aibom.drift import DriftKind, compare_scan_results
from aibom.export.cyclonedx import to_cyclonedx
from aibom.graph import build_graph
from aibom.impact import build_impact_paths
from aibom.models.entities import EntityType, Prompt
from aibom.models.findings import Severity
from aibom.report.html import render_html
from aibom.service import run_scan


def _scan(tmp_path: Path, code: str):  # noqa: ANN202
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return run_scan(tmp_path)


def test_directly_bound_command_tool_creates_critical_impact_path(
    tmp_path: Path,
) -> None:
    result = _scan(
        tmp_path,
        "import subprocess\n"
        "from agents import Agent, function_tool\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@function_tool\n"
        "def diagnose(command: str):\n"
        "    return subprocess.run(command, shell=True)\n"
        "@app.post('/support')\n"
        "def support(request):\n"
        '    rules = "Diagnose: " + request.issue\n'
        "    return Agent(name='ops', model='gpt-4.1', instructions=rules, "
        "tools=[diagnose])\n",
    )

    prompt = next(
        entity
        for entity in result.inventory.by_type(EntityType.PROMPT)
        if isinstance(entity, Prompt)
    )
    assert prompt.sink_kind == "openai.agents.Agent.instructions"
    assert prompt.tool_refs == ["diagnose"]
    assert prompt.capabilities[0].kind == "command_execution"
    assert prompt.capabilities[0].operation == "subprocess.run"
    assert prompt.capabilities[0].controlled_parameters == ["command"]
    assert prompt.capabilities[0].source_evidence[0].kind == "capability"

    paths = build_impact_paths(result.inventory)
    assert len(paths) == 1
    assert paths[0].severity is Severity.CRITICAL
    assert paths[0].binding == "direct_agent_tool_binding"
    assert paths[0].reachable.value == "true"
    assert paths[0].consequence == "execute operating-system commands"

    finding = next(
        item for item in result.findings if item.rule_id == "AIBOM-IMPACT-001"
    )
    assert finding.severity is Severity.CRITICAL
    assert "not proof that exploitation succeeds" in finding.description
    assert not any(item.rule_id == "AIBOM-PROMPT-004" for item in result.findings)

    graph = build_graph(result.inventory, result.findings)
    assert graph["impact_paths"][0]["tool_names"] == ["diagnose"]
    html = render_html(result.inventory, result.findings, result.score)
    assert "Potential blast radius" in html
    assert "subprocess.run" in html

    document = to_cyclonedx(result.inventory)
    component = next(
        item
        for item in document["components"]
        if item["name"].startswith("agent-instructions@")
    )
    properties = {
        (item["name"], item["value"]) for item in component["properties"]
    }
    assert ("aibom:prompt_tool_refs", "diagnose") in properties
    assert any(name == "aibom:prompt_bound_capability" for name, _ in properties)


def test_dangerous_helper_without_direct_recognized_binding_is_not_impact(
    tmp_path: Path,
) -> None:
    result = _scan(
        tmp_path,
        "import subprocess\n"
        "from agents import Agent, function_tool\n"
        "def unbound(command):\n"
        "    return subprocess.run(command, shell=True)\n"
        "@function_tool\n"
        "def weather(city):\n"
        "    return 'sunny'\n"
        "def build(request):\n"
        "    return Agent(name='safe', model='gpt-4.1', "
        "instructions=request.text, tools=[weather])\n",
    )
    assert not build_impact_paths(result.inventory)
    assert not any(
        item.rule_id == "AIBOM-IMPACT-001" for item in result.findings
    )


def test_same_components_can_gain_a_new_critical_blast_radius() -> None:
    paths = drift_demo_paths()
    assert paths is not None
    baseline, candidate = paths
    report = compare_scan_results(run_scan(baseline), run_scan(candidate))

    impact = next(
        item
        for item in report.changes
        if item.kind is DriftKind.IMPACT_PATH_ADDED
    )
    assert impact.severity is Severity.CRITICAL
    assert impact.details["tools"] == ["run_diagnostic"]
    assert impact.details["capabilities"][0]["operation"] == "subprocess.run"
    assert not any(
        item.kind is DriftKind.COMPONENT_ADDED for item in report.changes
    )


def test_undecorated_bound_function_is_not_promoted_to_impact(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import subprocess\n"
        "from agents import Agent\n"
        "def dangerous(command):\n"
        "    return subprocess.run(command, shell=True)\n"
        "def build(request):\n"
        "    return Agent(name='x', model='gpt-4.1', "
        "instructions=request.text, tools=[dangerous])\n",
    )
    prompt = next(
        entity
        for entity in result.inventory.by_type(EntityType.PROMPT)
        if isinstance(entity, Prompt)
    )
    assert prompt.tool_refs == ["dangerous"]
    assert prompt.capabilities == []
    assert not build_impact_paths(result.inventory)


def test_fixed_diagnostic_command_is_not_a_steerable_capability(
    tmp_path: Path,
) -> None:
    result = _scan(
        tmp_path,
        "import subprocess\n"
        "from agents import Agent, function_tool\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@function_tool\n"
        "def healthcheck(verbose: bool):\n"
        "    return subprocess.run(['uptime'], check=True)\n"
        "@app.post('/support')\n"
        "def support(request):\n"
        "    return Agent(name='ops', model='gpt-4.1', "
        "instructions=request.text, tools=[healthcheck])\n",
    )
    prompt = next(
        entity
        for entity in result.inventory.by_type(EntityType.PROMPT)
        if isinstance(entity, Prompt)
    )
    assert prompt.tool_refs == ["healthcheck"]
    assert prompt.capabilities == []
    assert not build_impact_paths(result.inventory)
