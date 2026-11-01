"""Offline Baseline -> Candidate -> Fixed scenarios for agent privilege drift."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from aibom.agent_security.analyzer import analyze
from aibom.agent_security.drift import compare_reports
from aibom.agent_security.models import AgentSecurityReport, PrivilegeDriftReport
from aibom.drift import compare_boms
from aibom.service import ScanResult, run_scan

STAGES = ("baseline", "candidate", "fixed")


@dataclass(frozen=True)
class Scenario:
    name: str
    bundled: str  # directory name inside the installed package
    changed: str  # the only file that differs, for the narration
    change: str  # what the candidate changes
    fix: str  # what the fixed revision restores


SCENARIOS: dict[str, Scenario] = {
    "agent-privilege-drift": Scenario(
        "agent-privilege-drift",
        "agent_privilege_demo",
        "policy/review-role.json",
        "the agent role policy gains s3:PutObject and s3:DeleteObject",
        "policy restored to least privilege",
    ),
    "mcp-tool-exposure": Scenario(
        "mcp-tool-exposure",
        "mcp_exposure_demo",
        "app/agent.py",
        "the agent's MCP tool_filter (allowed_tool_names=['read_asset']) is removed",
        "tool_filter restored",
    ),
}


def scenario_root(name: str = "agent-privilege-drift") -> Path | None:
    scenario = SCENARIOS[name]
    here = Path(__file__).resolve()
    for candidate in (
        here.parent.parent / scenario.bundled,
        here.parents[3] / "examples" / scenario.name,
    ):
        if all((candidate / stage / "app" / "agent.py").is_file() for stage in STAGES):
            return candidate
    return None


@dataclass
class ScenarioResult:
    scans: dict[str, ScanResult]
    reports: dict[str, AgentSecurityReport]
    introduced: PrivilegeDriftReport
    fixed: PrivilegeDriftReport
    residual: PrivilegeDriftReport


def scan_with_agents(path: Path, label: str) -> tuple[ScanResult, AgentSecurityReport]:
    result = run_scan(path, display_target=label)
    return result, analyze(path, result.inventory, display_target=label)


def run_scenario(root: Path, name: str = "agent-privilege-drift") -> ScenarioResult:
    scans: dict[str, ScanResult] = {}
    reports: dict[str, AgentSecurityReport] = {}
    for stage in STAGES:
        scans[stage], reports[stage] = scan_with_agents(root / stage, f"built-in://{name}/{stage}")

    def diff(left: str, right: str) -> PrivilegeDriftReport:
        bom = compare_boms(scans[left], scans[right])
        return compare_reports(
            reports[left],
            reports[right],
            bom_identical=bom.identical,
            bom_differences=[*bom.added, *bom.removed, *bom.changed],
            retest_command=f"aibom demo --scenario {name}",
        )

    return ScenarioResult(
        scans=scans,
        reports=reports,
        introduced=diff("baseline", "candidate"),
        fixed=diff("candidate", "fixed"),
        residual=diff("baseline", "fixed"),
    )


def write_artifacts(result: ScenarioResult, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for stage, report in result.reports.items():
        path = directory / f"{stage}.agent-security.json"
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        written.append(path)
    for name, report_ in (
        ("drift-baseline-candidate", result.introduced),
        ("drift-candidate-fixed", result.fixed),
        ("drift-baseline-fixed", result.residual),
    ):
        path = directory / f"{name}.json"
        path.write_text(report_.model_dump_json(indent=2), encoding="utf-8")
        written.append(path)
    summary = {
        "bom_unchanged": result.introduced.bom_components_unchanged,
        "introduced_changes": [c.type for c in result.introduced.changes],
        "remaining_after_fix": [c.type for c in result.residual.changes],
        "unknowns_after_fix": len(result.reports["fixed"].unknowns),
    }
    path = directory / "summary.json"
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    written.append(path)
    return written
