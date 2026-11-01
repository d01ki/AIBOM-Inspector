"""Coverage fixes found by the agent-security benchmark (one test per construct)."""

from __future__ import annotations

import json
from pathlib import Path

from aibom.agent_security.analyzer import analyze
from aibom.agent_security.models import AgentSecurityReport
from aibom.agent_security.operations import hazard_for_action, spec_for
from aibom.service import run_scan

MANIFEST = """\
schema_version: 1
agents: []
identities:
  - id: "aws:role/mcp"
    provider: aws
    policies: ["policy/mcp.json"]
mcp_servers:
  - source: "servers/storage.py"
    identity_ref: "aws:role/mcp"
"""
ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def _report(root: Path, files: dict[str, str]) -> AgentSecurityReport:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / "requirements.txt").write_text("openai-agents==0.2.10\nmcp==1.9.0\nboto3==1.35.0\n")
    (root / "aibom-identity.yaml").write_text(MANIFEST)
    (root / "policy").mkdir(exist_ok=True)
    (root / "policy" / "mcp.json").write_text(json.dumps({"Statement": [ALLOW_ALL]}))
    return analyze(root, run_scan(root).inventory)


def _server_tools(report: AgentSecurityReport) -> set[str]:
    return {t.name for s in report.mcp_servers for t in s.tools}


def _actions(report: AgentSecurityReport) -> set[str]:
    return {op.action for op in report.operations}


# -- IAM action derivation ---------------------------------------------------------------


def test_spec_for_prefers_table_then_derives_and_flags() -> None:
    tabled = spec_for("s3", "get_object")
    assert tabled is not None and not tabled.derived
    derived = spec_for("stepfunctions", "start_execution")
    assert derived is not None and derived.derived
    assert derived.action == "states:StartExecution"
    assert spec_for("s3", "list_buckets").action == "s3:ListAllMyBuckets"  # type: ignore[union-attr]
    assert spec_for("s3", "get_paginator") is None
    assert spec_for("s3", "_private") is None


def test_hazard_for_derived_actions() -> None:
    assert hazard_for_action("iam:CreateUser") == "admin"
    assert hazard_for_action("iam:GetUser") == "read"
    assert hazard_for_action("ec2:DetachVolume") == "delete"
    assert hazard_for_action("ssm:AddTagsToResource") == "write"
    assert hazard_for_action("cloudtrail:ListTrails") == "list"
    assert hazard_for_action("secretsmanager:GetSecretValue") == "secrets_read"
    assert hazard_for_action("s3:*") == "admin"


# -- MCP server definitions --------------------------------------------------------------


def test_mcpserver_rename_is_a_server_but_agents_client_is_not(tmp_path: Path) -> None:
    report = _report(
        tmp_path,
        {
            "servers/storage.py": (
                "from mcp.server.mcpserver import MCPServer\n\n"
                'srv = MCPServer("storage")\n\n\n'
                "@srv.tool()\ndef ping() -> str:\n    return 'pong'\n"
            ),
            "app/client.py": (
                "from agents.mcp import MCPServer\n\n"
                'other = MCPServer("not-a-server")\n\n\n'
                "@other.tool()\ndef nope() -> str:\n    return ''\n"
            ),
        },
    )
    assert _server_tools(report) == {"ping"}


def test_call_style_registration_of_methods_via_register(tmp_path: Path) -> None:
    tools = """\
import boto3


class TrailTools:
    def __init__(self) -> None:
        self.region = "us-east-1"

    def _client(self):
        return boto3.client("cloudtrail", region_name=self.region)

    def register(self, mcp) -> None:
        mcp.tool(name="lookup_events")(self.lookup_events)

    def lookup_events(self) -> dict:
        return self._client().lookup_events()
"""
    server = """\
from mcp.server.fastmcp import FastMCP

from servers.tools import TrailTools

mcp = FastMCP("trail")
TrailTools().register(mcp)
"""
    report = _report(
        tmp_path,
        {"servers/__init__.py": "", "servers/tools.py": tools, "servers/storage.py": server},
    )
    [srv] = report.mcp_servers
    assert [t.name for t in srv.tools] == ["lookup_events"]
    [op] = report.operations
    assert op.action == "cloudtrail:LookupEvents"
    assert op.derived_action
    assert op.tool_file == "servers/tools.py"


# -- boto3 client resolution -------------------------------------------------------------


def test_factory_session_and_parameterised_service(tmp_path: Path) -> None:
    server = """\
import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("storage")


def make(service_name: str):
    return boto3.client(service_name)


def s3_client():
    return boto3.Session().client("s3")


@mcp.tool()
def a() -> None:
    make("dynamodb").delete_table(TableName="t")


@mcp.tool()
def b() -> None:
    s3_client().get_object(Bucket="x", Key="k")


@mcp.tool()
def c() -> None:
    session = boto3.Session()
    session.client("sqs").send_message(QueueUrl="q", MessageBody="m")
"""
    report = _report(tmp_path, {"servers/storage.py": server})
    assert _actions(report) == {"dynamodb:DeleteTable", "s3:GetObject", "sqs:SendMessage"}


def test_factory_with_disagreeing_returns_is_unresolved(tmp_path: Path) -> None:
    server = """\
import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("storage")


def pick(flag: bool):
    if flag:
        return boto3.client("s3")
    return boto3.client("sqs")


@mcp.tool()
def a() -> None:
    pick(True).list_queues()
"""
    report = _report(tmp_path, {"servers/storage.py": server})
    assert _actions(report) == set()


# -- agents ------------------------------------------------------------------------------

AGENTS_PY = """\
from agents import Agent, handoff


class Out:
    pass


helper = Agent(name="Helper", instructions="x")
typed = Agent[Out](name="Typed", instructions="x")
as_tool = helper.as_tool(tool_name="help", tool_description="h")
boss = Agent(name="Boss", instructions="x", tools=[as_tool])
router = Agent(name="Router", instructions="x")
router.handoffs.append(handoff(agent=helper))
router.handoffs.extend([typed])
"""


def test_generic_agent_appended_handoffs_and_variable_as_tool(tmp_path: Path) -> None:
    report = _report(tmp_path, {"app/agents_app.py": AGENTS_PY})
    names = {a.display_name for a in report.agents}
    assert names == {"Helper", "Typed", "Boss", "Router"}
    edges = {
        (d.parent_id.rsplit(":", 1)[-1], d.mechanism, (d.child_id or "").rsplit(":", 1)[-1])
        for d in report.delegations
    }
    assert edges == {
        ("boss", "agent_as_tool", "helper"),
        ("router", "handoff", "helper"),
        ("router", "handoff", "typed"),
    }
    assert not any(u.reason == "tool_binding_unresolved" for u in report.unknowns)


# -- agent-side MCP connections ----------------------------------------------------------

STORAGE_SERVER = """\
import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("storage")
s3 = boto3.client("s3")


@mcp.tool()
def read_asset(key: str) -> str:
    return s3.get_object(Bucket="b", Key=key)


@mcp.tool()
def purge_asset(key: str) -> None:
    s3.delete_object(Bucket="b", Key=key)
"""


def _agent(approval: str) -> str:
    return f"""\
from agents import Agent
from agents.mcp import MCPServerStdio


def build(server):
    return Agent(name="A", instructions="x", mcp_servers=[server])


async def main() -> None:
    params = {{"command": "python", "args": ["servers/storage.py"]}}
    async with MCPServerStdio(params=params{approval}) as storage:
        build(storage)
"""


def test_client_passed_as_parameter_is_resolved_one_hop(tmp_path: Path) -> None:
    report = _report(
        tmp_path, {"servers/storage.py": STORAGE_SERVER, "app/agent.py": _agent("")}
    )
    [connection] = [c for c in report.mcp_connections if c.client_kind == "agent"]
    assert connection.server_id is not None
    assert connection.approval == "none"
    assert {p.action for p in report.capability_paths if p.via == "mcp"} == {
        "s3:GetObject",
        "s3:DeleteObject",
    }


def test_require_approval_per_tool_marks_only_listed_tools(tmp_path: Path) -> None:
    approval = ', require_approval={"always": {"tool_names": ["purge_asset"]}}'
    report = _report(
        tmp_path, {"servers/storage.py": STORAGE_SERVER, "app/agent.py": _agent(approval)}
    )
    [connection] = [c for c in report.mcp_connections if c.client_kind == "agent"]
    assert connection.approval == "per_tool"
    marked = {
        p.action: "human-approval-required" in p.constraints
        for p in report.capability_paths
        if p.via == "mcp"
    }
    assert marked == {"s3:GetObject": False, "s3:DeleteObject": True}


def test_require_approval_always_and_unresolved(tmp_path: Path) -> None:
    report = _report(
        tmp_path,
        {
            "servers/storage.py": STORAGE_SERVER,
            "app/agent.py": _agent(', require_approval="always"'),
        },
    )
    [connection] = [c for c in report.mcp_connections if c.client_kind == "agent"]
    assert connection.approval == "always"
    paths = [p for p in report.capability_paths if p.via == "mcp"]
    assert paths and all("human-approval-required" in p.constraints for p in paths)

    other = tmp_path / "other"
    report = _report(
        other,
        {
            "servers/storage.py": STORAGE_SERVER,
            "app/agent.py": _agent(", require_approval=policy"),
        },
    )
    [connection] = [c for c in report.mcp_connections if c.client_kind == "agent"]
    assert connection.approval == "unresolved"
