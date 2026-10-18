"""Run other publicly available scanners next to AIBOM Inspector on the same inputs.

This is an experiment, not a documentation review: every row in the report is
produced by actually running the tool named in it. Tools are not dependencies of
this project; pass the path of each installed executable. A tool that is not
given is reported as "not run", never as "cannot".

Two questions are measured, and kept apart on purpose:

1. **Identical-BOM drift.** For each baseline/candidate pair (same components,
   one changed prompt builder), does the tool's own revision-comparison mode
   flag the candidate? For a tool that diffs against a saved baseline, both
   revisions are copied to the *same* temporary path before scanning, so
   finding fingerprints that include file paths do not create spurious "new"
   findings. AIBOM Inspector compares the two checked-in directories, as
   ``aibom diff`` does.
2. **Negative controls.** How many findings each tool reports on the pinned
   corpus repositories whose ground truth contains no AI component. This is a
   count, not a false-positive rate: a competitor may legitimately report
   non-AI issues (secrets, packaging) that are outside AIBOM's scope.

Nothing scanned is executed by this harness. The tools are invoked in their
static modes only (no ``--dynamic``, no MCP ``inspect``, no LLM).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from aibom.drift import compare_scan_results
from aibom.models.findings import Severity
from aibom.service import run_scan

ROOT = Path(__file__).resolve().parents[2]

# (name, baseline, candidate, what changed)
DRIFT_PAIRS = (
    (
        "same-file Python",
        "examples/trust-boundary-drift/baseline",
        "examples/trust-boundary-drift/candidate",
        "message moved from the user turn into the system prompt",
    ),
    (
        "same-file Python, bound tool",
        "tests/fixtures/impact-demo-baseline",
        "tests/fixtures/impact-demo",
        "untrusted input reaches Agent.instructions; tool unchanged",
    ),
    (
        "same-file TypeScript, bound tool",
        "tests/fixtures/impact-demo-ts-baseline",
        "tests/fixtures/impact-demo-ts",
        "untrusted input reaches generateText({ system }); tool unchanged",
    ),
    (
        "cross-file Python (4 files)",
        "tests/fixtures/xfile-py-baseline",
        "tests/fixtures/xfile-py-candidate",
        "prompt builder appends the request parameter",
    ),
    (
        "cross-file TypeScript (4 files)",
        "tests/fixtures/xfile-ts-baseline",
        "tests/fixtures/xfile-ts-candidate",
        "prompt builder appends the request parameter",
    ),
)

_AIBOM_GATE = Severity.HIGH


@dataclass
class ToolRun:
    tool: str
    flagged: bool | None
    detail: str
    baseline_findings: int | None = None
    candidate_findings: int | None = None


@dataclass
class DriftCase:
    name: str
    baseline: str
    candidate: str
    change: str
    runs: list[ToolRun] = field(default_factory=list)


@dataclass
class NegativeCase:
    repository: str
    commit: str
    counts: dict[str, int | str] = field(default_factory=dict)


def _copy_to(src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)


def _clean_env() -> dict[str, str]:
    """Environment without LLM credentials, so no tool can silently call one."""
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AIBOM_LLM", "OPENAI_", "ANTHROPIC_", "AI_DEFENSE"))
    }


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=_clean_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )


# --- AIBOM Inspector -------------------------------------------------------


def _aibom_drift(baseline: Path, candidate: Path) -> ToolRun:
    before = run_scan(baseline, lockfiles=False)
    after = run_scan(candidate, lockfiles=False)
    report = compare_scan_results(before, after)
    gating = [
        change
        for change in report.changes
        if change.gates and change.severity.rank >= _AIBOM_GATE.rank
    ]
    kinds = sorted({f"{c.severity.value} {c.kind.value}" for c in gating})
    bom = "BOM identical" if report.bom and report.bom.identical else "BOM changed"
    return ToolRun(
        tool="aibom",
        flagged=bool(gating),
        detail=f"{bom}; " + (", ".join(kinds) if kinds else "no gating change"),
        baseline_findings=len(before.findings),
        candidate_findings=len(after.findings),
    )


def _aibom_count(path: Path) -> int:
    result = run_scan(path, lockfiles=False)
    return sum(1 for f in result.findings if f.severity.rank >= _AIBOM_GATE.rank)


# --- agent-audit -----------------------------------------------------------


def _agent_audit_scan(exe: str, cwd: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    out = cwd.parent / f"agent-audit-{cwd.name}.json"
    proc = _run([exe, "-q", "scan", ".", "--format", "json", "-o", str(out), *extra], cwd)
    data = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else {}
    out.unlink(missing_ok=True)
    return proc.returncode, data


def _actionable(data: dict[str, Any], minimum: str = "high") -> int:
    order = ["info", "low", "medium", "high", "critical"]
    floor = order.index(minimum)
    return sum(
        1
        for f in data.get("findings", [])
        if not f.get("suppressed") and order.index(f.get("severity", "info")) >= floor
    )


def _agent_audit_drift(exe: str, baseline: Path, candidate: Path, work: Path) -> ToolRun:
    rev = work / "rev"
    saved = work / "agent-audit-baseline.json"
    _copy_to(baseline, rev)
    _, before = _agent_audit_scan(exe, rev, "--save-baseline", str(saved))
    _copy_to(candidate, rev)
    _, after = _agent_audit_scan(exe, rev)
    code, new = _agent_audit_scan(
        exe, rev, "--baseline", str(saved), "--fail-on-new", "--fail-on", "high"
    )
    new_high = _actionable(new)
    detail = (
        f"--baseline/--fail-on-new exit {code}; {new_high} new high+ finding(s); "
        f"rules before {_rules(before)}, after {_rules(after)}"
    )
    note = _relocation_note(before, new)
    if note:
        detail += f"; {note}"
    return ToolRun(
        tool="agent-audit",
        flagged=code != 0 or new_high > 0,
        detail=detail,
        baseline_findings=_actionable(before),
        candidate_findings=_actionable(after),
    )


def _relocation_note(before: dict[str, Any], new: dict[str, Any]) -> str:
    """Explain "new" findings whose rule already fired in the same baseline file.

    Such a finding is a fingerprint change (typically a line shift), not a
    detected behavioral change.
    """
    added = _rule_files(new)
    relocated = sorted(f"{rule} {path}" for rule, path in added & _rule_files(before))
    if not relocated:
        return ""
    if len(relocated) == len(added):
        return (
            "every new finding repeats a baseline rule in the same file "
            f"({', '.join(relocated)}): line-shift artifact"
        )
    return f"some new findings repeat a baseline rule ({', '.join(relocated)})"


def _rule_files(data: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (f["rule_id"], f["location"]["file_path"])
        for f in data.get("findings", [])
        if not f.get("suppressed")
    }


def _rules(data: dict[str, Any]) -> str:
    rules = sorted({f["rule_id"] for f in data.get("findings", []) if not f.get("suppressed")})
    return "[" + ", ".join(rules) + "]"


# --- cisco-aibom -----------------------------------------------------------


def _cisco_probe(exe: str, target: Path) -> str:
    """Record what the tool does when asked to run without an LLM."""
    proc = _run([exe, "analyze", str(target), "--output-format", "json"], ROOT)
    text = (proc.stdout + proc.stderr).strip().splitlines()
    first = next((line.strip() for line in text if line.strip()), "")
    return f"exit {proc.returncode}: {first}"


def _version(exe: str, distribution: str) -> str:
    """Installed version, read from the tool's own environment when it has one."""
    python = Path(exe).with_name("python.exe" if os.name == "nt" else "python")
    if python.is_file():
        proc = _run(
            [
                str(python),
                "-c",
                f"import importlib.metadata as m; print(m.version({distribution!r}))",
            ],
            ROOT,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    proc = _run([exe, "--version"], ROOT)
    return (
        proc.stdout.strip().splitlines()[0] if proc.returncode == 0 and proc.stdout else "unknown"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--agent-audit", help="Path to the agent-audit executable.")
    parser.add_argument("--cisco-aibom", help="Path to the cisco-aibom executable.")
    parser.add_argument(
        "--ground-truth-dir", type=Path, default=ROOT / "benchmark" / "ground_truth_public"
    )
    parser.add_argument(
        "--json", type=Path, default=ROOT / "benchmark" / "reports" / "competitors-latest.json"
    )
    parser.add_argument(
        "--markdown", type=Path, default=ROOT / "benchmark" / "reports" / "competitors-latest.md"
    )
    args = parser.parse_args(argv)

    tools: dict[str, str] = {"aibom": "this checkout"}
    if args.agent_audit:
        tools["agent-audit"] = _version(args.agent_audit, "agent-audit")
    if args.cisco_aibom:
        tools["cisco-aibom"] = _version(args.cisco_aibom, "cisco-aibom")

    drift: list[DriftCase] = []
    with tempfile.TemporaryDirectory(prefix="aibom-competitors-") as tmp:
        work = Path(tmp)
        for name, base, cand, change in DRIFT_PAIRS:
            case = DriftCase(name, base, cand, change)
            case.runs.append(_aibom_drift(ROOT / base, ROOT / cand))
            if args.agent_audit:
                case.runs.append(
                    _agent_audit_drift(args.agent_audit, ROOT / base, ROOT / cand, work)
                )
            drift.append(case)
            print(f"drift: {name}", file=sys.stderr)

    negatives: list[NegativeCase] = []
    for doc_path in sorted(args.ground_truth_dir.glob("*.json")):
        doc = json.loads(doc_path.read_text(encoding="utf-8"))
        if doc.get("components"):
            continue
        local = ROOT / doc["local_path"]
        neg = NegativeCase(doc["repository"], doc["commit"])
        if not local.is_dir():
            neg.counts = dict.fromkeys(tools, "checkout missing")
        else:
            neg.counts["aibom"] = _aibom_count(local)
            if args.agent_audit:
                with tempfile.TemporaryDirectory(prefix="aibom-competitors-") as tmp:
                    rev = Path(tmp) / "rev"
                    _copy_to(local, rev)
                    _, data = _agent_audit_scan(args.agent_audit, rev)
                    neg.counts["agent-audit"] = _actionable(data)
        negatives.append(neg)
        print(f"negative: {neg.repository}", file=sys.stderr)

    cisco = _cisco_probe(args.cisco_aibom, ROOT / DRIFT_PAIRS[3][2]) if args.cisco_aibom else None
    refused = "refused (LLM required)" if cisco and "llm" in cisco.lower() else None

    report = {
        "tools": tools,
        "gate": f"{_AIBOM_GATE.value}+",
        "drift": [asdict(case) for case in drift],
        "negative_controls": [asdict(neg) for neg in negatives],
        "cisco_aibom_without_llm": cisco,
        "not_run_reason": {"cisco-aibom": refused} if refused else {},
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    args.markdown.write_text(_markdown(report), encoding="utf-8", newline="\n")
    return 0


def _not_run(report: dict[str, Any], tool: str) -> str:
    return str(report["not_run_reason"].get(tool) or "not run")


def _cell(run: dict[str, Any]) -> str:
    if run["flagged"] is None:
        return "n/a"
    if not run["flagged"]:
        return "not flagged"
    return "flagged (line-shift artifact)" if "line-shift artifact" in run["detail"] else "flagged"


def _markdown(report: dict[str, Any]) -> str:
    tools = list(report["tools"])
    lines = [
        "# Competitor comparison (experiment)",
        "",
        "Generated by `benchmark/competitors/compare.py`. Every cell comes from running",
        "the tool; a tool not listed was not run.",
        "",
        "| Tool | Version |",
        "|---|---|",
        *(f"| {tool} | {version} |" for tool, version in report["tools"].items()),
        "",
        "## Identical-BOM drift",
        "",
        f"Gate: {report['gate']}. *Flagged* means the tool's own revision-comparison",
        "mode would fail CI on the candidate.",
        "",
        "| Pair | Change | " + " | ".join(tools) + " |",
        "|---|---|" + "---|" * len(tools),
    ]
    for case in report["drift"]:
        by_tool = {run["tool"]: run for run in case["runs"]}
        cells = [_cell(by_tool[t]) if t in by_tool else _not_run(report, t) for t in tools]
        lines.append(f"| {case['name']} | {case['change']} | " + " | ".join(cells) + " |")
    lines += ["", "Details:", ""]
    for case in report["drift"]:
        lines.append(f"- **{case['name']}** (`{case['baseline']}` → `{case['candidate']}`)")
        for run in case["runs"]:
            lines.append(
                f"  - {run['tool']}: {run['detail']} "
                f"(high+ findings: baseline {run['baseline_findings']}, "
                f"candidate {run['candidate_findings']})"
            )
    lines += [
        "",
        "## Negative controls",
        "",
        "High+ findings on pinned corpus repositories whose ground truth has no AI",
        "component. A count, not a false-positive rate (see the script docstring).",
        "",
        "| Repository | Commit | " + " | ".join(tools) + " |",
        "|---|---|" + "---|" * len(tools),
    ]
    for neg in report["negative_controls"]:
        cells = [str(neg["counts"].get(t, _not_run(report, t))) for t in tools]
        lines.append(
            f"| {neg['repository']} | `{neg['commit'][:12]}` | " + " | ".join(cells) + " |"
        )
    if report["cisco_aibom_without_llm"]:
        lines += [
            "",
            "## cisco-aibom without an LLM",
            "",
            "`cisco-aibom analyze <cross-file candidate> --output-format json`, with no",
            "LLM variables in the environment:",
            "",
            f"> {report['cisco_aibom_without_llm']}",
        ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
