"""Agent and MCP tool inventory with a reachability ladder (P1 capability graph).

declared -> registered (MCP) -> bound (agent) -> potentially_reachable.
A description or a name never makes a tool dangerous; only a parameter proven
to reach a recognized operation does.  MCP servers are parsed, never started.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from aibom.drift import DriftKind, compare_scan_results
from aibom.export.cyclonedx import to_cyclonedx_json
from aibom.inventory import Inventory
from aibom.models.entities import RelationshipType, Tool
from aibom.service import run_scan

FIXTURES = Path(__file__).parent / "fixtures"

PY_MCP = '''\
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def run(command: str) -> str:
    """Run anything."""
    return subprocess.run(command, shell=True, capture_output=True).stdout


@mcp.tool()
def uptime() -> str:
    """Delete everything, says the description; the code does not."""
    return subprocess.run(["uptime"], capture_output=True).stdout
'''

TS_MCP = """\
import { execSync } from 'node:child_process';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'ops', version: '1.0.0' });

server.tool('run', {}, async ({ command }) => ({ out: execSync(command) }));
server.registerTool('status', {}, async () => ({ out: execSync('uptime') }));
server.tool('external', {}, handlerFromElsewhere);
"""


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _tools(inventory: Inventory) -> dict[str, Tool]:
    return {e.tool_name: e for e in inventory.entities if isinstance(e, Tool)}


def test_python_mcp_tool_with_command_parameter_is_potentially_reachable(
    tmp_path: Path,
) -> None:
    tools = _tools(run_scan(_write(tmp_path, {"server.py": PY_MCP})).inventory)
    assert tools["run"].framework == "mcp"
    assert tools["run"].state == "potentially_reachable"
    assert tools["run"].trust_boundary == "tool_caller_to_application"
    assert [c.kind for c in tools["run"].capabilities] == ["command_execution"]
    # A frightening description with a fixed command is still not a capability.
    assert tools["uptime"].state == "registered"
    assert tools["uptime"].capabilities == []


def test_typescript_mcp_registrations(tmp_path: Path) -> None:
    files = {
        "src/server.ts": TS_MCP,
        "package.json": '{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}',
    }
    tools = _tools(run_scan(_write(tmp_path, files)).inventory)
    assert tools["run"].state == "potentially_reachable"
    assert tools["run"].capabilities[0].controlled_parameters == ["command"]
    assert tools["status"].state == "registered"
    # The handler is not resolvable: shown as unknown, never as safe or capable.
    assert tools["external"].state == "unknown"


def test_agent_tool_states_follow_the_prompt_analysis() -> None:
    baseline = _tools(run_scan(FIXTURES / "xfile-py-baseline").inventory)["run_diagnostic"]
    candidate_inventory = run_scan(FIXTURES / "xfile-py-candidate").inventory
    candidate = _tools(candidate_inventory)["run_diagnostic"]
    assert baseline.state == "bound"
    assert candidate.state == "potentially_reachable"
    assert candidate.bound_by == ["agent-instructions@assistant/main.py:12"]
    assert any(
        r.relationship is RelationshipType.INVOKES and r.target_id == candidate.id
        for r in candidate_inventory.relationships
    )


def test_unbound_declared_tool_stays_declared(tmp_path: Path) -> None:
    source = (
        "import subprocess\nfrom agents import function_tool\n\n\n@function_tool\n"
        "def shell(command: str) -> None:\n    subprocess.run(command, shell=True)\n"
    )
    tool = _tools(run_scan(_write(tmp_path, {"tools.py": source})).inventory)["shell"]
    assert tool.state == "declared"
    assert tool.capabilities  # capable, but nothing binds or registers it


def test_typescript_tool_factory_is_recorded(tmp_path: Path) -> None:
    root = tmp_path / "app"
    shutil.copytree(FIXTURES / "xfile-ts-candidate", root)
    (root / "lib" / "tools" / "factory.ts").write_text(
        "import { tool } from 'ai';\n"
        "export const makeNote = (deps: unknown) => tool({ execute: async ({ text }) => text });\n",
        encoding="utf-8",
    )
    tools = _tools(run_scan(root).inventory)
    assert tools["makeNote"].state == "declared"
    assert tools["runDiagnostic"].state == "potentially_reachable"


def test_identical_bom_ignores_tool_state(tmp_path: Path) -> None:
    report = compare_scan_results(
        run_scan(FIXTURES / "xfile-py-baseline"), run_scan(FIXTURES / "xfile-py-candidate")
    )
    assert report.bom is not None and report.bom.identical is True
    assert "tool" in report.bom.compared_types
    # The impact path already explains the bound tool; it is not reported twice.
    assert DriftKind.TOOL_REACHABILITY_ESCALATED not in {c.kind for c in report.changes}


def test_new_mcp_shell_tool_is_a_boundary_change(tmp_path: Path) -> None:
    baseline = _write(tmp_path / "base", {"server.py": PY_MCP.split("@mcp.tool()\ndef run")[0]})
    candidate = _write(tmp_path / "cand", {"server.py": PY_MCP})
    report = compare_scan_results(run_scan(baseline), run_scan(candidate))
    [change] = [c for c in report.changes if c.kind is DriftKind.TOOL_REACHABILITY_ESCALATED]
    assert change.severity.value == "high"  # never Critical on registration alone
    assert change.details["after_state"] == "potentially_reachable"
    assert report.security_boundary_changed is True


def test_tool_component_exports_state_and_capabilities(tmp_path: Path) -> None:
    document = json.loads(
        to_cyclonedx_json(run_scan(_write(tmp_path, {"server.py": PY_MCP})).inventory)
    )
    props = [
        (p["name"], p["value"])
        for component in document["components"]
        for p in component.get("properties", [])
    ]
    assert ("aibom:tool_state", "potentially_reachable") in props
    assert any(name == "aibom:tool_capability" for name, _ in props)
