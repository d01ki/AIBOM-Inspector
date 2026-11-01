"""Agent identity, bounded IAM evaluation and privilege drift (design doc §8)."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aibom.agent_security import iam
from aibom.agent_security.analyzer import analyze
from aibom.agent_security.drift import compare_reports
from aibom.agent_security.models import AgentSecurityReport, Verdict
from aibom.agent_security.safeio import InputError, load_structured
from aibom.agent_security.scenario import run_scenario, scenario_root
from aibom.cli import app
from aibom.drift import compare_boms
from aibom.service import run_scan

AGENT_PY = """\
import boto3
from agents import Agent, function_tool

BUCKET = "demo-assets"
s3 = boto3.client("s3")


@function_tool
def read_asset(key: str) -> str:
    return s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()


@function_tool
def publish_review(key: str, body: str) -> str:
    s3.put_object(Bucket=BUCKET, Key=key, Body=body)
    return "ok"


@function_tool
def purge_asset(key: str) -> str:
    s3.delete_object(Bucket=BUCKET, Key=key)
    return "deleted"


reviewer = Agent(
    name="Reviewer",
    instructions="Review assets.",
    tools=[read_asset, publish_review],
)
"""

MANIFEST = """\
schema_version: 1
agents:
  - agent_ref: "agent:reviewer"
    source: "app/agent.py:reviewer"
    identity_ref: "aws:role/review"
identities:
  - id: "aws:role/review"
    provider: aws
    policies: ["policy/role.json"]
"""

GET = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo-assets/*"}
PUT = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::demo-assets/*"}


def _project(
    root: Path,
    statements: list[dict[str, object]] | None,
    *,
    manifest: str = MANIFEST,
    code: str = AGENT_PY,
    indent: int = 2,
) -> Path:
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "agent.py").write_text(code, encoding="utf-8")
    (root / "requirements.txt").write_text("openai-agents==0.2.10\nboto3==1.35.0\n")
    (root / "aibom-identity.yaml").write_text(manifest, encoding="utf-8")
    if statements is not None:
        (root / "policy").mkdir(exist_ok=True)
        document = {"Version": "2012-10-17", "Statement": statements}
        (root / "policy" / "role.json").write_text(json.dumps(document, indent=indent))
    return root


def _report(root: Path) -> AgentSecurityReport:
    return analyze(root, run_scan(root).inventory, display_target=root.name)


def _paths(report: AgentSecurityReport) -> dict[str, Verdict]:
    return {path.action: path.verdict for path in report.capability_paths}


def _diff(tmp_path: Path, before: list[dict[str, object]], after: list[dict[str, object]]):
    left = _project(tmp_path / "baseline", before)
    right = _project(tmp_path / "candidate", after)
    bom = compare_boms(run_scan(left), run_scan(right))
    return compare_reports(_report(left), _report(right), bom_identical=bom.identical)


# -- capability paths ----------------------------------------------------------------


def test_bound_tools_form_paths_and_unbound_tool_does_not(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, [GET]))
    assert _paths(report) == {
        "s3:GetObject": Verdict.POTENTIALLY_ALLOWED,
        "s3:PutObject": Verdict.NO_MATCHING_ALLOW,
    }
    # purge_asset performs DeleteObject but is not bound: operation known, no path.
    assert any(op.action == "s3:DeleteObject" for op in report.operations)
    assert all(path.tool_name != "purge_asset" for path in report.capability_paths)
    allowed = next(p for p in report.capability_paths if p.action == "s3:GetObject")
    assert allowed.proven is False
    assert "identity-policy-only" in allowed.constraints
    assert any(ev.pointer == "/Statement/0" for ev in allowed.evidence)


def test_tool_ids_match_the_aibom_inventory(tmp_path: Path) -> None:
    root = _project(tmp_path, [GET])
    inventory = run_scan(root).inventory
    report = analyze(root, inventory)
    inventory_ids = {e.id for e in inventory.entities if e.type.value == "tool"}
    assert {p.tool_id for p in report.capability_paths} <= inventory_ids


def test_explicit_deny_wins_over_allow(tmp_path: Path) -> None:
    deny = {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
    report = _report(_project(tmp_path, [GET, deny]))
    assert set(_paths(report).values()) == {Verdict.EXPLICITLY_DENIED}


@pytest.mark.parametrize(
    "statement",
    [
        {**GET, "Condition": {"Bool": {"aws:SecureTransport": "true"}}},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::other/*"},
    ],
)
def test_unsupported_elements_are_unknown_not_allowed(
    tmp_path: Path, statement: dict[str, object]
) -> None:
    report = _report(_project(tmp_path, [statement]))
    assert _paths(report)["s3:GetObject"] is Verdict.UNKNOWN
    assert any(u.reason == "unsupported_policy_elements" for u in report.unknowns)


def test_unevaluable_deny_turns_allow_into_unknown(tmp_path: Path) -> None:
    deny = {"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"x": {}}}
    report = _report(_project(tmp_path, [GET, deny]))
    assert _paths(report)["s3:GetObject"] is Verdict.UNKNOWN


def test_missing_policy_file_is_unknown_with_reason(tmp_path: Path) -> None:
    report = _report(_project(tmp_path, None))
    assert set(_paths(report).values()) == {Verdict.UNKNOWN}
    assert any(u.reason == "policy_missing" for u in report.unknowns)


def test_undefined_identity_is_unknown(tmp_path: Path) -> None:
    manifest = MANIFEST.replace('identity_ref: "aws:role/review"', 'identity_ref: "aws:role/x"')
    report = _report(_project(tmp_path, [GET], manifest=manifest))
    assert set(_paths(report).values()) == {Verdict.UNKNOWN}
    assert any(u.reason == "identity_undefined" for u in report.unknowns)


def test_unmapped_agent_is_never_bound_by_name(tmp_path: Path) -> None:
    manifest = MANIFEST.replace("app/agent.py:reviewer", "app/agent.py:someone_else")
    report = _report(_project(tmp_path, [GET], manifest=manifest))
    assert report.agents[0].identity_id is None
    assert {u.reason for u in report.unknowns} >= {"identity_unmapped", "manifest_agent_unresolved"}


def test_same_agent_name_in_two_files_keeps_identities_apart(tmp_path: Path) -> None:
    root = _project(tmp_path, [GET])
    (root / "billing").mkdir()
    (root / "billing" / "agent.py").write_text(AGENT_PY, encoding="utf-8")
    (root / "policy" / "billing.json").write_text(
        json.dumps({"Statement": [PUT, GET]}), encoding="utf-8"
    )
    manifest = MANIFEST + (
        '  - id: "aws:role/billing"\n    provider: aws\n    policies: ["policy/billing.json"]\n'
    )
    manifest = manifest.replace(
        "identities:",
        '  - agent_ref: "agent:billing-reviewer"\n'
        '    source: "billing/agent.py:reviewer"\n'
        '    identity_ref: "aws:role/billing"\n'
        "identities:",
    )
    (root / "aibom-identity.yaml").write_text(manifest, encoding="utf-8")
    report = _report(root)
    by_agent = {(p.agent_id, p.action): (p.identity_id, p.verdict) for p in report.capability_paths}
    assert by_agent[("agent:reviewer", "s3:PutObject")] == (
        "aws:role/review",
        Verdict.NO_MATCHING_ALLOW,
    )
    assert by_agent[("agent:billing-reviewer", "s3:PutObject")] == (
        "aws:role/billing",
        Verdict.POTENTIALLY_ALLOWED,
    )


def test_ambiguous_agent_variable_gets_no_identity(tmp_path: Path) -> None:
    code = AGENT_PY + (
        "\n\ndef rebuild():\n"
        '    reviewer = Agent(name="R2", instructions="x", tools=[publish_review])\n'
        "    return reviewer\n"
    )
    report = _report(_project(tmp_path, [GET], code=code))
    assert all(agent.identity_id is None for agent in report.agents)
    assert any(u.reason == "agent_source_ambiguous" for u in report.unknowns)


# -- privilege drift -------------------------------------------------------------------


def test_policy_only_change_is_permission_scope_expanded(tmp_path: Path) -> None:
    drift = _diff(tmp_path, [GET], [GET, PUT])
    assert drift.bom_components_unchanged is True
    assert drift.security_drift is True
    [change] = [c for c in drift.changes if c.gates]
    assert change.type == "permission_scope_expanded"
    assert change.action == "s3:PutObject"
    assert change.before == ["s3:GetObject"]
    assert change.after == ["s3:GetObject", "s3:PutObject"]
    assert change.certainty == "conditional"
    assert change.severity == "high"
    assert any("#/Statement/1" in ref for ref in change.evidence)
    assert change.remediation is not None and change.remediation.retest_command


def test_permission_reduction_is_removal_without_new_findings(tmp_path: Path) -> None:
    drift = _diff(tmp_path, [GET, PUT], [GET])
    assert [c.type for c in drift.changes] == ["potential_privilege_removed"]
    assert not any(c.gates for c in drift.changes)
    assert drift.security_drift is False


def test_reformatting_policy_and_code_is_not_drift(tmp_path: Path) -> None:
    left = _project(tmp_path / "a", [GET])
    right = _project(tmp_path / "b", [GET], code="\n\n\n" + AGENT_PY, indent=8)
    drift = compare_reports(_report(left), _report(right))
    assert drift.changes == []


def test_unknown_to_allowed_is_review_required(tmp_path: Path) -> None:
    conditional = {**PUT, "Condition": {"StringEquals": {"aws:RequestTag/x": "y"}}}
    drift = _diff(tmp_path, [GET, conditional], [GET, PUT])
    [change] = [c for c in drift.changes if c.action == "s3:PutObject"]
    assert change.type == "review_required"
    assert change.change_status == "review_required"
    assert change.gates is False
    assert change.severity != "critical"


def test_grant_without_tool_operation_is_identity_level_only(tmp_path: Path) -> None:
    delete = {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"}
    drift = _diff(tmp_path, [GET], [GET, delete])
    [change] = drift.changes
    assert change.type == "identity_permission_expanded"
    assert change.agent is None
    assert change.severity == "medium"


def test_missing_policy_on_one_side_never_yields_critical(tmp_path: Path) -> None:
    left = _project(tmp_path / "a", None)
    right = _project(tmp_path / "b", [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    drift = compare_reports(_report(left), _report(right))
    assert all(c.severity != "critical" for c in drift.changes)
    assert all(c.type == "review_required" for c in drift.changes if c.agent)
    assert drift.scope_mismatch


# -- input safety ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_ref", ["../outside.json", "/etc/passwd", "C:/Windows/win.ini", "https://x/p.json"]
)
def test_policy_paths_outside_workspace_are_rejected(tmp_path: Path, policy_ref: str) -> None:
    manifest = MANIFEST.replace('["policy/role.json"]', f'["{policy_ref}"]')
    root = _project(tmp_path / "ws", [GET], manifest=manifest)
    with pytest.raises(InputError):
        analyze(root)


def test_symlink_escaping_workspace_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"Statement": [GET]}))
    root = _project(tmp_path / "ws", None)
    (root / "policy").mkdir()
    try:
        os.symlink(outside, root / "policy" / "role.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    with pytest.raises(InputError):
        analyze(root)


def test_credentials_in_manifest_are_rejected_without_echo(tmp_path: Path) -> None:
    secret = "AKIAFAKEFAKEFAKE1234"
    manifest = MANIFEST + f'aws_secret_access_key: "{secret}"\n'
    root = _project(tmp_path, [GET], manifest=manifest)
    with pytest.raises(InputError) as excinfo:
        analyze(root)
    assert secret not in str(excinfo.value)


def test_secret_strings_in_sources_never_reach_the_report(tmp_path: Path) -> None:
    secret = "sk-test-DO-NOT-LEAK-0123456789"
    code = AGENT_PY.replace('BUCKET = "demo-assets"', f'BUCKET = "demo-assets"\nKEY = "{secret}"')
    root = _project(tmp_path, [{**GET, "Sid": "ReadAssets"}], code=code)
    report = _report(root)
    assert secret not in report.model_dump_json()


@pytest.mark.parametrize(
    "text",
    [
        "a: &anchor 1\nb: *anchor\n",
        "a: !!python/object:os.system x\n",
        "a: |\n  block\n",
        "a: 1\n---\nb: 2\n",
    ],
)
def test_yaml_subset_rejects_unsafe_constructs(text: str) -> None:
    with pytest.raises(InputError):
        load_structured(text, label="m")


def test_yaml_subset_parses_the_documented_shape() -> None:
    data = load_structured(MANIFEST, label="m")
    assert data["agents"][0]["source"] == "app/agent.py:reviewer"
    assert data["identities"][0]["policies"] == ["policy/role.json"]


# -- IAM evaluator units -------------------------------------------------------------------


def test_iam_wildcards_and_partial_resources() -> None:
    policy = iam.parse_policy_document(
        "p.json",
        {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::b/r/*"}]},
    )
    covered = iam.evaluate([policy], "s3:getobject", "arn:aws:s3:::b/r/x", resource_resolved=True)
    assert covered.verdict is Verdict.POTENTIALLY_ALLOWED
    overlap = iam.evaluate([policy], "s3:GetObject", "arn:aws:s3:::b/*", resource_resolved=False)
    assert overlap.verdict is Verdict.UNKNOWN
    other = iam.evaluate([policy], "s3:GetObject", "arn:aws:s3:::c/*", resource_resolved=False)
    assert other.verdict is Verdict.NO_MATCHING_ALLOW
    assert iam.evaluate([], "s3:GetObject", "*", resource_resolved=False).verdict is Verdict.UNKNOWN


# -- CLI and demo ---------------------------------------------------------------------------


def test_bundled_scenario_baseline_candidate_fixed() -> None:
    root = scenario_root()
    assert root is not None
    result = run_scenario(root)
    assert result.introduced.bom_components_unchanged is True
    assert [c.type for c in result.introduced.changes if c.gates] == ["permission_scope_expanded"]
    assert not [c for c in result.residual.changes if c.gates]
    assert result.residual.changes == []


def test_cli_scan_adds_agent_security_namespace(tmp_path: Path) -> None:
    root = _project(tmp_path / "ws", [GET])
    plain, enriched = tmp_path / "plain.json", tmp_path / "enriched.json"
    runner = CliRunner()
    assert runner.invoke(app, ["scan", str(root), "-q", "-o", str(plain)]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "scan",
            str(root),
            "-q",
            "-o",
            str(enriched),
            "--identity-manifest",
            "aibom-identity.yaml",
        ],
    )
    assert result.exit_code == 0, result.output
    before, after = json.loads(plain.read_text()), json.loads(enriched.read_text())
    assert set(after) - set(before) == {"agent_security"}
    assert after["agent_security"]["schema_version"] == "1.0"


def test_cli_diff_agent_privileges_gates_and_writes(tmp_path: Path) -> None:
    left = _project(tmp_path / "baseline", [GET])
    right = _project(tmp_path / "candidate", [GET, PUT])
    out = tmp_path / "drift.json"
    result = CliRunner().invoke(
        app,
        ["diff", str(left), str(right), "--agent-privileges", "-o", str(out), "--fail-on", "high"],
    )
    assert result.exit_code == 1, result.output
    data = json.loads(out.read_text())
    assert data["agent_privileges"]["bom_components_unchanged"] is True
    assert data["bom"]["identical"] is True


def test_cli_rejects_escaping_manifest(tmp_path: Path) -> None:
    root = _project(tmp_path / "ws", [GET])
    result = CliRunner().invoke(
        app, ["scan", str(root), "-q", "--identity-manifest", "../aibom-identity.yaml"]
    )
    assert result.exit_code == 2


def test_cli_demo_scenario(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["demo", "--scenario", "agent-privilege-drift", "--output-dir", str(tmp_path / "o")],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads((tmp_path / "o" / "summary.json").read_text())
    assert summary == {
        "bom_unchanged": True,
        "introduced_changes": ["permission_scope_expanded", "identity_permission_expanded"],
        "remaining_after_fix": [],
        "unknowns_after_fix": 0,
    }
    shutil.rmtree(tmp_path / "o")
