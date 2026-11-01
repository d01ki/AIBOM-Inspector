"""P1: helper/cross-file operations, delegation, approved-agent registry, SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aibom.agent_security.analyzer import analyze
from aibom.agent_security.drift import compare_reports
from aibom.agent_security.models import AgentSecurityReport, Verdict
from aibom.agent_security.sarif import to_sarif
from aibom.cli import app
from aibom.service import run_scan

GET = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo-assets/*"}
PUT = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::demo-assets/*"}

CLIENTS_PY = 'import boto3\n\ns3 = boto3.client("s3")\n'

STORAGE_PY = """\
from app.clients import s3


def upload(key: str, body: str) -> None:
    _store(key, body)


def _store(key: str, body: str) -> None:
    s3.put_object(Bucket="demo-assets", Key=key, Body=body)
    upload(key, body)  # recursion must not loop forever
"""

AGENT_PY = """\
from agents import Agent, function_tool, handoff

from app.clients import s3
from app.storage import upload


@function_tool
def read_asset(key: str) -> str:
    return s3.get_object(Bucket="demo-assets", Key=key)["Body"].read()


@function_tool
def publish_review(key: str, body: str) -> str:
    upload(key, body)
    return "ok"


reviewer = Agent(name="Reviewer", instructions="Review.", tools=[read_asset, publish_review])
triage = Agent(name="Triage", instructions="Route.", handoffs=[handoff(agent=reviewer)])
orchestrator = Agent(
    name="Orchestrator",
    instructions="Coordinate.",
    tools=[reviewer.as_tool(tool_name="review", tool_description="Review"), read_asset],
)
dispatcher = Agent(name="Dispatcher", instructions="x", handoffs=[missing_agent])
"""

MANIFEST = """\
schema_version: 1
agents:
  - agent_ref: "agent:reviewer"
    source: "app/agent.py:reviewer"
    identity_ref: "aws:role/review"
  - agent_ref: "agent:orchestrator"
    source: "app/agent.py:orchestrator"
    identity_ref: "aws:role/review"
identities:
  - id: "aws:role/review"
    provider: aws
    policies: ["policy/role.json"]
"""


def _project(root: Path, statements: list[dict[str, object]], *, code: str = AGENT_PY) -> Path:
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "clients.py").write_text(CLIENTS_PY)
    (root / "app" / "storage.py").write_text(STORAGE_PY)
    (root / "app" / "agent.py").write_text(code)
    (root / "requirements.txt").write_text("openai-agents==0.2.10\nboto3==1.35.0\n")
    (root / "aibom-identity.yaml").write_text(MANIFEST)
    (root / "policy").mkdir(exist_ok=True)
    (root / "policy" / "role.json").write_text(json.dumps({"Statement": statements}))
    return root


def _report(root: Path, **kwargs: object) -> AgentSecurityReport:
    return analyze(root, run_scan(root).inventory, **kwargs)  # type: ignore[arg-type]


def _registry(path: Path, *refs: str) -> Path:
    lines = ["schema_version: 1", "agents:"]
    lines += [f'  - agent_ref: "{ref}"' for ref in refs]
    path.write_text("\n".join(lines) + "\n")
    return path


# -- P1-B helper and cross-file operations ----------------------------------------------


def test_operation_through_cross_file_helper_and_imported_client(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, [GET, PUT]))
    paths = {(p.agent_id, p.tool_name, p.action): p for p in report.capability_paths}
    put = paths[("agent:reviewer", "publish_review", "s3:PutObject")]
    assert put.verdict is Verdict.POTENTIALLY_ALLOWED
    assert put.resource == "arn:aws:s3:::demo-assets/*"
    trail = [e.ref() for e in put.evidence]
    assert "app/agent.py:14" in trail  # tool -> upload()
    assert "app/storage.py:5" in trail  # upload -> _store()
    assert "app/storage.py:9" in trail  # the put_object call
    get = paths[("agent:reviewer", "read_asset", "s3:GetObject")]
    assert get.verdict is Verdict.POTENTIALLY_ALLOWED


# -- P1-C delegation ---------------------------------------------------------------------


def test_delegations_are_resolved_but_never_merged(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, [GET, PUT]))
    edges = {(d.parent_id, d.mechanism): d.child_id for d in report.delegations}
    assert edges[("agent:app/agent.py:triage", "handoff")] == "agent:reviewer"
    assert edges[("agent:orchestrator", "agent_as_tool")] == "agent:reviewer"
    assert edges[("agent:app/agent.py:dispatcher", "handoff")] is None
    assert any(u.reason == "delegate_unresolved" for u in report.unknowns)

    triage_own = [p for p in report.capability_paths if p.agent_id.endswith(":triage")]
    assert triage_own == []  # the child's capabilities are not the parent's
    delegated = [p for p in report.delegate_paths if p.parent_id.endswith(":triage")]
    assert {p.action for p in delegated} == {"s3:GetObject", "s3:PutObject"}
    assert all(p.verdict is Verdict.UNKNOWN for p in delegated)
    assert all("delegation_guard_unverified" in p.reasons for p in delegated)
    assert any(e.kind == "DELEGATES_TO" for e in report.edges)


def test_agent_as_tool_keeps_function_tools_bound(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, [GET]))
    orchestrator = next(a for a in report.agents if a.id == "agent:orchestrator")
    assert len(orchestrator.tool_ids) == 1  # read_asset; review is a delegation
    own = {p.action for p in report.capability_paths if p.agent_id == "agent:orchestrator"}
    assert own == {"s3:GetObject"}


def test_delegate_path_added_is_review_required(tmp_path: Path) -> None:
    before = _report(_project(tmp_path / "a", [GET]))
    after = _report(_project(tmp_path / "b", [GET, PUT]))
    drift = compare_reports(before, after)
    delegated = [c for c in drift.changes if c.type == "delegate_path_added"]
    assert {c.agent for c in delegated} == {"agent:app/agent.py:triage", "agent:orchestrator"}
    assert all(c.change_status == "review_required" and not c.gates for c in delegated)
    assert all(c.severity in {"low", "medium"} for c in delegated)
    scope = [c for c in drift.changes if c.type == "permission_scope_expanded"]
    assert [c.agent for c in scope] == ["agent:reviewer"]


# -- P1-D approved-agent registry --------------------------------------------------------


def test_without_registry_status_is_unknown_even_if_target_has_one(tmp_path: Path) -> None:
    root = _project(tmp_path, [GET])
    _registry(root / "approved_agents.yaml", "agent:reviewer")  # must not be auto-read
    report = _report(root)
    assert {a.management_status for a in report.agents} == {"unknown"}


def test_registry_marks_agents_and_drift_flags_new_unregistered(tmp_path: Path) -> None:
    registry = _registry(
        tmp_path / "approved.yaml",
        "agent:reviewer",
        "agent:orchestrator",
        "APP/agent.py:triage",  # alias by source, case-insensitive
    )
    before_code = AGENT_PY.replace(
        'dispatcher = Agent(name="Dispatcher", instructions="x", handoffs=[missing_agent])\n', ""
    )
    before = _report(_project(tmp_path / "a", [GET], code=before_code), registry=registry)
    after = _report(_project(tmp_path / "b", [GET]), registry=registry)
    status = {a.id: a.management_status for a in after.agents}
    assert status["agent:reviewer"] == "registered"
    assert status["agent:app/agent.py:triage"] == "registered"
    assert status["agent:app/agent.py:dispatcher"] == "unregistered"
    drift = compare_reports(before, after)
    [change] = [c for c in drift.changes if c.type == "unregistered_agent_added"]
    assert change.agent == "agent:app/agent.py:dispatcher"
    assert change.gates is True


# -- SARIF ----------------------------------------------------------------------------------


def test_privilege_sarif_has_rules_locations_and_skips_removals(tmp_path: Path) -> None:
    before = _report(_project(tmp_path / "a", [GET]))
    after = _report(_project(tmp_path / "b", [GET, PUT]))
    log = to_sarif(compare_reports(before, after))
    results = log["runs"][0]["results"]
    rules = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert {"AIBOM-AGENT-001", "AIBOM-AGENT-006"} <= rules
    scope = next(r for r in results if r["ruleId"] == "AIBOM-AGENT-001")
    region = scope["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "app/storage.py"
    assert region["region"]["startLine"] == 9
    assert scope["level"] == "error"
    removed = to_sarif(compare_reports(after, before))["runs"][0]["results"]
    assert removed == []


def test_cli_diff_writes_agent_sarif_and_requires_flag(tmp_path: Path) -> None:
    left = _project(tmp_path / "a", [GET])
    right = _project(tmp_path / "b", [GET, PUT])
    sarif = tmp_path / "agents.sarif"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["diff", str(left), str(right), "-q", "--agent-privileges", "--agent-sarif", str(sarif)],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(sarif.read_text())["version"] == "2.1.0"
    missing = runner.invoke(app, ["diff", str(left), str(right), "-q", "--agent-sarif", str(sarif)])
    assert missing.exit_code == 2


def test_cli_scan_with_registry_only(tmp_path: Path) -> None:
    root = _project(tmp_path / "ws", [GET])
    registry = _registry(tmp_path / "approved.yaml", "agent:reviewer")
    out = tmp_path / "inv.json"
    result = CliRunner().invoke(
        app, ["scan", str(root), "-q", "-o", str(out), "--agent-registry", str(registry)]
    )
    assert result.exit_code == 0, result.output
    agents = json.loads(out.read_text())["agent_security"]["agents"]
    assert {a["id"]: a["management_status"] for a in agents}["agent:reviewer"] == "registered"
