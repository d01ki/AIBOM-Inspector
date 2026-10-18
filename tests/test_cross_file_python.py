"""Bounded cross-file prompt flow and tool binding for Python.

Positive: a route, a prompt builder, an agent factory and a tool module in four
files.  Negative and unknown cases pin the precision contract: a path that
cannot be proven is never promoted to a Critical impact, and an unresolved
construct is never reported as safe.
"""

from __future__ import annotations

import time
from pathlib import Path

from aibom.impact import build_impact_paths
from aibom.inventory import Inventory
from aibom.models.analysis import Reachability
from aibom.models.entities import Prompt
from aibom.service import run_scan

FIXTURES = Path(__file__).parent / "fixtures"
REQUIREMENTS = "fastapi==0.115.0\nopenai-agents==0.3.0\n"

ROUTE = '''\
from fastapi import FastAPI

from assistant.main import run_support_agent

app = FastAPI()


@app.post("/support")
def support(problem: str) -> dict[str, str]:
    return {"agent": run_support_agent(problem).name}
'''

AGENT = '''\
from agents import Agent

from prompts.builder import build_instructions
from tools.executor import run_diagnostic


def run_support_agent(problem: str) -> Agent:
    return Agent(
        name="ops",
        model="gpt-4.1",
        instructions=build_instructions(problem),
        tools=[{tools}],
    )
'''

BUILDER = '''\
POLICY = "Use only the approved runbooks."


def build_instructions(problem: str) -> str:
    return {body}
'''

TOOL = '''\
import subprocess

from agents import function_tool


@function_tool
def run_diagnostic(command: str) -> str:
    {body}
    return "done"
'''


def _project(
    root: Path,
    *,
    builder: str = 'POLICY + "\\nProblem: " + problem',
    tool: str = "subprocess.run(command, shell=True)",
    tools: str = "run_diagnostic",
    extra: dict[str, str] | None = None,
) -> Inventory:
    files = {
        "requirements.txt": REQUIREMENTS,
        "routes/api.py": ROUTE,
        "assistant/main.py": AGENT.replace("{tools}", tools),
        "prompts/builder.py": BUILDER.replace("{body}", builder),
        "tools/executor.py": TOOL.replace("{body}", tool),
        **(extra or {}),
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return run_scan(root).inventory


def _system_prompt(inventory: Inventory) -> Prompt:
    prompts = [e for e in inventory.entities if isinstance(e, Prompt) and e.kind == "system"]
    assert len(prompts) == 1, [p.name for p in prompts]
    return prompts[0]


def _operations(prompt: Prompt) -> list[str]:
    return [step.operation for step in prompt.data_flow_path]


# -- positive -----------------------------------------------------------------


def test_four_file_path_is_proven_with_evidence_in_every_file() -> None:
    inventory = run_scan(FIXTURES / "xfile-py-candidate").inventory
    prompt = _system_prompt(inventory)

    assert prompt.user_controlled is True
    assert prompt.source_kind == "http_parameter"
    assert prompt.usage.reachable is Reachability.TRUE
    assert prompt.reachability_path[0] == "http_route:support"
    assert prompt.tool_refs == ["run_diagnostic"]
    [capability] = prompt.capabilities
    assert capability.kind == "command_execution"
    assert capability.controlled_parameters == ["command"]

    flow_files = {step.file for step in prompt.data_flow_path}
    assert {"routes/api.py", "prompts/builder.py", "assistant/main.py"} <= flow_files
    evidence_files = {item.file for item in capability.source_evidence}
    assert evidence_files == {"tools/executor.py"}  # tool body + helper operation
    assert {"call_argument", "call_return", "return_value"} <= set(_operations(prompt))
    assert "unresolved_call" not in _operations(prompt)

    [path] = build_impact_paths(inventory)
    assert path.severity.value == "critical"
    assert path.reachable is Reachability.TRUE
    # Nothing secret or prompt-like is serialized along the path.
    assert all(step.value is None for step in prompt.data_flow_path)
    assert "approved runbooks" not in prompt.model_dump_json()


def test_identical_bom_baseline_with_sanitizing_helper_has_no_path() -> None:
    inventory = run_scan(FIXTURES / "xfile-py-baseline").inventory
    prompt = _system_prompt(inventory)
    assert prompt.user_controlled is False
    assert prompt.capabilities  # the tool is still bound and still powerful
    assert build_impact_paths(inventory) == []


def test_imported_module_constant_is_followed(tmp_path: Path) -> None:
    inventory = _project(
        tmp_path,
        builder="PREFIX + problem",
        extra={"prompts/__init__.py": "", "prompts/text.py": 'PREFIX = "Problem: "\n'},
    )
    builder = tmp_path / "prompts" / "builder.py"
    builder.write_text("from prompts.text import PREFIX\n" + builder.read_text(), "utf-8")
    inventory = run_scan(tmp_path).inventory
    prompt = _system_prompt(inventory)
    assert prompt.user_controlled is True


# -- negative -----------------------------------------------------------------


def test_user_role_only_flow_is_not_privileged(tmp_path: Path) -> None:
    files = {
        "requirements.txt": "fastapi==0.115.0\nopenai==1.50.0\n",
        "routes/api.py": ROUTE,
        "assistant/main.py": '''\
from openai import OpenAI

from prompts.builder import build_user_message

client = OpenAI()


def run_support_agent(problem: str):
    return client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": "Use only the approved runbooks."},
            {"role": "user", "content": build_user_message(problem)},
        ],
    )
''',
        "prompts/builder.py": "def build_user_message(problem):\n    return 'Q: ' + problem\n",
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    inventory = run_scan(tmp_path).inventory
    prompts = {p.kind: p for p in inventory.entities if isinstance(p, Prompt)}
    assert prompts["user"].user_controlled is True
    assert prompts["system"].user_controlled is False
    assert build_impact_paths(inventory) == []


def test_unbound_tool_in_another_file_is_not_a_capability(tmp_path: Path) -> None:
    inventory = _project(tmp_path, tools="")
    prompt = _system_prompt(inventory)
    assert prompt.user_controlled is True
    assert prompt.capabilities == []
    assert build_impact_paths(inventory) == []


def test_fixed_command_is_not_model_controlled(tmp_path: Path) -> None:
    inventory = _project(tmp_path, tool='subprocess.run(["uptime"], check=True)')
    assert _system_prompt(inventory).capabilities == []
    assert build_impact_paths(inventory) == []


def test_helper_returning_constants_sanitizes_the_flow(tmp_path: Path) -> None:
    inventory = _project(
        tmp_path,
        builder="POLICY + _label(problem)\n\n\ndef _label(raw):\n    return 'general'",
    )
    assert _system_prompt(inventory).user_controlled is False
    assert build_impact_paths(inventory) == []


def test_commented_out_binding_is_ignored(tmp_path: Path) -> None:
    inventory = _project(tmp_path, tools="\n        # run_diagnostic\n    ")
    assert _system_prompt(inventory).capabilities == []


# -- unknown ------------------------------------------------------------------


def test_dynamic_builder_is_potential_not_proven(tmp_path: Path) -> None:
    inventory = _project(
        tmp_path,
        builder='getattr(__import__("prompts.styles"), "render")(problem)',
    )
    prompt = _system_prompt(inventory)
    # Tainted input flows into a call the index cannot see: kept, but marked.
    assert prompt.user_controlled is True
    assert "unresolved_call" in _operations(prompt)


def test_reflective_constant_stays_unknown(tmp_path: Path) -> None:
    inventory = _project(tmp_path, builder='importlib.import_module("prompts.text").POLICY')
    prompt = _system_prompt(inventory)
    assert prompt.user_controlled is None
    assert build_impact_paths(inventory) == []


def test_tool_from_ambiguous_module_is_not_resolved(tmp_path: Path) -> None:
    tool = TOOL.replace("{body}", "subprocess.run(command, shell=True)")
    inventory = _project(
        tmp_path / "repo",
        extra={"svc_a/tools/executor.py": tool, "svc_b/tools/executor.py": tool},
    )
    # `tools.executor` matches tools/executor.py exactly, so it is resolved...
    [capability] = _system_prompt(inventory).capabilities
    assert {item.file for item in capability.source_evidence} == {"tools/executor.py"}

    (tmp_path / "repo" / "tools" / "executor.py").unlink()
    inventory = run_scan(tmp_path / "repo").inventory
    # ...but with only svc_a/ and svc_b/ candidates left, nothing is guessed.
    assert _system_prompt(inventory).capabilities == []


# -- stability ----------------------------------------------------------------


def test_cyclic_imports_and_recursion_terminate(tmp_path: Path) -> None:
    inventory = _project(
        tmp_path,
        builder="POLICY + helpers.a.ping(problem)",
        extra={
            "helpers/__init__.py": "",
            "helpers/a.py": "from helpers.b import pong\n\n\ndef ping(x):\n    return pong(x)\n",
            "helpers/b.py": "from helpers.a import ping\n\n\ndef pong(x):\n    return ping(x)\n",
        },
    )
    builder = tmp_path / "prompts" / "builder.py"
    builder.write_text("import helpers.a\n" + builder.read_text(), "utf-8")
    inventory = run_scan(tmp_path).inventory
    prompt = _system_prompt(inventory)
    assert prompt.user_controlled in {True, None}
    assert "cycle" in _operations(prompt)


def test_syntax_error_elsewhere_does_not_break_the_path(tmp_path: Path) -> None:
    inventory = _project(tmp_path, extra={"broken.py": "def oops(:\n"})
    assert any("broken.py" in item for item in inventory.stats.parse_errors)
    assert _system_prompt(inventory).user_controlled is True


def test_long_helper_chain_is_bounded(tmp_path: Path) -> None:
    extra = {"chain/__init__.py": ""}
    for index in range(40):
        extra[f"chain/m{index}.py"] = (
            f"from chain.m{index + 1} import f{index + 1}\n\n\n"
            f"def f{index}(x):\n    return f{index + 1}(x)\n"
        )
    extra["chain/m40.py"] = "def f40(x):\n    return x\n"
    started = time.monotonic()
    inventory = _project(
        tmp_path, builder="POLICY + f0(problem)", extra=extra
    )
    builder = tmp_path / "prompts" / "builder.py"
    builder.write_text("from chain.m0 import f0\n" + builder.read_text(), "utf-8")
    inventory = run_scan(tmp_path).inventory
    assert time.monotonic() - started < 20
    prompt = _system_prompt(inventory)
    # The chain is deeper than the call bound: not proven, and never "safe".
    assert prompt.user_controlled is not False
