"""P1-A: static MCP capability graph (client -> server -> tool), never started."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aibom.agent_security.analyzer import analyze
from aibom.agent_security.drift import compare_reports
from aibom.agent_security.models import AgentSecurityReport, Verdict
from aibom.agent_security.safeio import InputError
from aibom.agent_security.scenario import run_scenario, scenario_root
from aibom.cli import app
from aibom.service import run_scan

SERVER_PY = """\
import subprocess

import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("storage")
s3 = boto3.client("s3")


@mcp.tool()
def read_asset(key: str) -> str:
    return s3.get_object(Bucket="demo-assets", Key=key)["Body"].read()


@mcp.tool()
def purge_asset(key: str) -> str:
    s3.delete_object(Bucket="demo-assets", Key=key)
    return "deleted"


@mcp.tool()
def run_maintenance(command: str) -> str:
    subprocess.run(command, shell=True)
    return "done"


def not_a_tool(key: str) -> None:
    s3.put_object(Bucket="demo-assets", Key=key, Body=b"")
"""

AGENT_PY = """\
from agents import Agent
from agents.mcp import MCPServerStdio, create_static_tool_filter

storage = MCPServerStdio(
    name="storage",
    params={{"command": "python", "args": ["servers/storage.py"]}},
    {filter}
)
reviewer = Agent(name="Reviewer", instructions="Review.", mcp_servers=[storage])
"""

MANIFEST = """\
schema_version: 1
agents:
  - agent_ref: "agent:reviewer"
    source: "app/agent.py:reviewer"
    identity_ref: "aws:role/agent"
{servers}identities:
  - id: "aws:role/agent"
    provider: aws
    policies: ["policy/agent.json"]
  - id: "aws:role/mcp"
    provider: aws
    policies: ["policy/mcp.json"]
"""
SERVER_MAPPING = (
    'mcp_servers:\n  - source: "servers/storage.py"\n    identity_ref: "aws:role/mcp"\n'
)
DENY_ALL = {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
MCP_GRANTS = {
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:DeleteObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::demo-assets/*",
}
FILTERED = 'tool_filter=create_static_tool_filter(allowed_tool_names=["read_asset"]),'


def _project(
    root: Path,
    *,
    tool_filter: str = FILTERED,
    server_mapping: bool = True,
    agent_code: str | None = None,
) -> Path:
    for sub in ("app", "servers", "policy"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "servers" / "storage.py").write_text(SERVER_PY)
    (root / "app" / "agent.py").write_text(agent_code or AGENT_PY.format(filter=tool_filter))
    (root / "requirements.txt").write_text("openai-agents==0.2.10\nmcp==1.9.0\n")
    (root / "aibom-identity.yaml").write_text(
        MANIFEST.format(servers=SERVER_MAPPING if server_mapping else "")
    )
    (root / "policy" / "agent.json").write_text(json.dumps({"Statement": [DENY_ALL]}))
    (root / "policy" / "mcp.json").write_text(json.dumps({"Statement": [MCP_GRANTS]}))
    return root


def _report(root: Path) -> AgentSecurityReport:
    return analyze(root, run_scan(root).inventory)


def _mcp_paths(report: AgentSecurityReport) -> dict[str, Verdict]:
    return {p.action: p.verdict for p in report.capability_paths if p.via == "mcp"}


def test_server_tools_and_static_filter(tmp_path: Path) -> None:
    report = _report(_project(tmp_path))
    [server] = report.mcp_servers
    assert server.status == "connected"
    assert [t.name for t in server.tools] == ["read_asset", "purge_asset", "run_maintenance"]
    maintenance = next(t for t in server.tools if t.name == "run_maintenance")
    assert maintenance.capability_kinds == ["command_execution"]
    assert maintenance.capability_severity == "critical"
    # Only the allowed tool is exposed; the undecorated helper never is.
    assert _mcp_paths(report) == {"s3:GetObject": Verdict.POTENTIALLY_ALLOWED}
    [agent] = report.agents
    assert len(agent.mcp_tool_ids) == 1
    kinds = {e.kind for e in report.edges}
    assert {"CONNECTS_MCP", "EXPOSES_TOOL", "RUNS_AS"} <= kinds


def test_mcp_paths_use_the_server_identity_not_the_agent(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, tool_filter=""))
    paths = [p for p in report.capability_paths if p.via == "mcp"]
    assert {p.identity_id for p in paths} == {"aws:role/mcp"}
    assert _mcp_paths(report)["s3:DeleteObject"] is Verdict.POTENTIALLY_ALLOWED
    assert all("mcp-server-identity" in p.constraints for p in paths)


def test_unmapped_server_identity_is_unknown(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, tool_filter="", server_mapping=False))
    assert set(_mcp_paths(report).values()) == {Verdict.UNKNOWN}
    assert all(
        "mcp_server_identity_unmapped" in p.reasons
        for p in report.capability_paths
        if p.via == "mcp"
    )


def test_blocked_and_dict_filters(tmp_path: Path) -> None:
    blocked = 'tool_filter={"blocked_tool_names": ["run_maintenance", "purge_asset"]},'
    report = _report(_project(tmp_path, tool_filter=blocked))
    assert set(_mcp_paths(report)) == {"s3:GetObject"}


def test_unresolved_filter_is_conservative_and_unknown(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, tool_filter="tool_filter=pick_tools,"))
    assert set(_mcp_paths(report)) == {"s3:GetObject", "s3:DeleteObject"}
    assert any(u.reason == "mcp_tool_filter_unresolved" for u in report.unknowns)
    assert all(
        "tool-filter-unresolved" in p.constraints
        for p in report.capability_paths
        if p.via == "mcp" and p.verdict is Verdict.POTENTIALLY_ALLOWED
    )


def test_async_with_client_and_remote_server(tmp_path: Path) -> None:
    code = """\
from agents import Agent
from agents.mcp import MCPServerStdio, MCPServerStreamableHttp


async def main() -> None:
    params = {"command": "uv", "args": ["run", "./servers/storage.py"]}
    async with MCPServerStdio(params=params) as local:
        remote = MCPServerStreamableHttp(params={"url": "https://mcp.example.invalid/mcp"})
        agent = Agent(name="A", instructions="x", mcp_servers=[local, remote])
"""
    report = _report(_project(tmp_path, agent_code=code))
    connections = {c.transport: c for c in report.mcp_connections if c.client_kind == "agent"}
    assert connections["stdio"].server_id is not None
    assert connections["stdio"].launch == "uv servers/storage.py"
    assert connections["streamable_http"].unresolved_reason == "remote_server_tools_unknown"
    assert "mcp.example.invalid" not in report.model_dump_json()


def test_server_outside_sources_is_unknown(tmp_path: Path) -> None:
    code = AGENT_PY.format(filter="").replace("servers/storage.py", "/opt/elsewhere/server.py")
    report = _report(_project(tmp_path, agent_code=code))
    assert any(u.reason == "server_outside_analyzed_sources" for u in report.unknowns)
    assert _mcp_paths(report) == {}


def test_client_config_is_configured_not_bound(tmp_path: Path) -> None:
    root = _project(tmp_path, agent_code="from agents import Agent\n")
    token = "ghp_FAKEFAKEFAKEFAKEFAKE0123456789"
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "storage": {
                        "command": "python",
                        "args": ["servers/storage.py", "--token", token],
                        "env": {"API_TOKEN": token},
                    },
                    "remote": {"url": "https://mcp.example.invalid/sse"},
                }
            }
        )
    )
    report = _report(root)
    [server] = report.mcp_servers
    assert server.status == "configured"
    assert report.capability_paths == []  # no analyzed agent binds it
    configured = [c for c in report.mcp_connections if c.client_kind == "config"]
    assert {c.server_label for c in configured} == {"storage", "remote"}
    dumped = report.model_dump_json()
    assert token not in dumped and "mcp.example.invalid" not in dumped


def test_unparsable_client_config_is_unknown(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "mcp.json").write_text("{not json")
    report = _report(root)
    assert any(u.reason == "config_unparsable" for u in report.unknowns)


def test_manifest_rejects_bad_mcp_server_source(tmp_path: Path) -> None:
    root = _project(tmp_path)
    text = (
        (root / "aibom-identity.yaml")
        .read_text()
        .replace("servers/storage.py", "servers/storage.py:mcp")
    )
    (root / "aibom-identity.yaml").write_text(text)
    with pytest.raises(InputError):
        analyze(root)


def test_widened_filter_is_exposure_drift(tmp_path: Path) -> None:
    before = _report(_project(tmp_path / "a"))
    after = _report(_project(tmp_path / "b", tool_filter=""))
    drift = compare_reports(before, after)
    exposure = {c.action: c for c in drift.changes if c.type == "mcp_tool_exposure_added"}
    assert set(exposure) == {"mcp:purge_asset", "mcp:run_maintenance"}
    assert exposure["mcp:run_maintenance"].severity == "critical"
    assert exposure["mcp:run_maintenance"].gates is True
    added = [c for c in drift.changes if c.type == "privilege_path_added"]
    assert [c.action for c in added] == ["s3:DeleteObject"]
    assert added[0].identity == "aws:role/mcp"


def test_bundled_mcp_scenario() -> None:
    root = scenario_root("mcp-tool-exposure")
    assert root is not None
    result = run_scenario(root, "mcp-tool-exposure")
    assert result.introduced.bom_components_unchanged is True
    kinds = sorted(c.type for c in result.introduced.changes if c.gates)
    assert kinds == ["mcp_tool_exposure_added", "mcp_tool_exposure_added", "privilege_path_added"]
    assert result.residual.changes == []


def test_cli_demo_mcp_scenario(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["demo", "--scenario", "mcp-tool-exposure", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["bom_unchanged"] is True
    assert summary["remaining_after_fix"] == []
