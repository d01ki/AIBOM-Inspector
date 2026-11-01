"""The offline Baseline -> Candidate -> Fixed agent-privilege-drift scenario."""

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


def scenario_root() -> Path | None:
    here = Path(__file__).resolve()
    for candidate in (
        here.parent.parent / "agent_privilege_demo",
        here.parents[3] / "examples" / "agent-privilege-drift",
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


def run_scenario(root: Path) -> ScenarioResult:
    scans: dict[str, ScanResult] = {}
    reports: dict[str, AgentSecurityReport] = {}
    for stage in STAGES:
        scans[stage], reports[stage] = scan_with_agents(
            root / stage, f"built-in://agent-privilege-drift/{stage}"
        )

    def diff(left: str, right: str) -> PrivilegeDriftReport:
        bom = compare_boms(scans[left], scans[right])
        return compare_reports(
            reports[left],
            reports[right],
            bom_identical=bom.identical,
            bom_differences=[*bom.added, *bom.removed, *bom.changed],
            retest_command="aibom demo --scenario agent-privilege-drift",
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
