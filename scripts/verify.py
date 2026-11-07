"""Verify a change against the feature map and collect evidence.

The completion criterion for any change in this repository is *executed checks
with evidence*, not an agent's (or a human's) statement that it works.

    python scripts/verify.py                 # features touched since the base branch
    python scripts/verify.py --all           # full sweep, in feature-map order
    python scripts/verify.py --feature dependency-map --no-ui
    python scripts/verify.py --files src/aibom/graph.py
    python scripts/verify.py --list          # show the change -> feature mapping only

What runs, per affected feature (read from ``docs/feature-map/*.md``):

* gates: ``ruff check`` and ``mypy`` (once, when Python changed or on ``--all``)
* the feature's pytest files (each file runs once, however many features list it)
* the feature's smoke commands (real CLI runs; exit code, output, and files checked)
* the feature's UI fixtures through ``scripts/verify_ui.py`` (headless Chromium)
* the feature's manual items, which are always reported NOT RUN

Every check ends in exactly one of four states:

    PASS     ran, and every expectation held
    FAIL     ran, and an expectation did not hold
    BLOCKED  could not run (tool or browser missing, timeout)
    NOT RUN  deliberately not executed (manual item, --no-ui, skipped tests)

A skipped test is not a passed test: skips are reported as their own NOT RUN
check. Evidence (command, exit code, duration, redacted log) lands in
``verify-out/<timestamp>-<sha>/``, with ``report.json`` and ``report.md``.

Exit code: 1 if anything FAILED, else 2 if anything is BLOCKED, else 0.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FEATURE_DIR = ROOT / "docs" / "feature-map"
INDEX = ROOT / "docs" / "feature-map.md"

PASS, FAIL, BLOCKED, NOT_RUN = "PASS", "FAIL", "BLOCKED", "NOT RUN"
STATUSES = (PASS, FAIL, BLOCKED, NOT_RUN)
_SEVERITY = {FAIL: 3, BLOCKED: 2, NOT_RUN: 1, PASS: 0}

_VERIFY_BLOCK = re.compile(r"```json verify\s*\n(.*?)\n```", re.S)

# Credentials must never reach an evidence log.
_SECRET_PATTERNS = [
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{16,}"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[=:]\s*)[^\s'\"]{8,}"),
]


# ── model ────────────────────────────────────────────────────────────────────


@dataclass
class Feature:
    id: str
    doc: str
    paths: list[str]
    tests: list[str] = field(default_factory=list)
    smoke: list[dict[str, Any]] = field(default_factory=list)
    ui: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)


@dataclass
class Check:
    id: str
    kind: str  # gate | tests | skipped-tests | smoke | ui | manual
    name: str
    status: str
    features: list[str]
    reason: str = ""
    cmd: list[str] = field(default_factory=list)
    exit_code: int | None = None
    expected_exit: int | None = None
    duration_s: float | None = None
    log: str | None = None
    artifacts: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


# ── feature map ──────────────────────────────────────────────────────────────


def load_features(feature_dir: Path = FEATURE_DIR, index: Path = INDEX) -> list[Feature]:
    """Features in the index's table order (the sweep order)."""
    order = re.findall(r"\(feature-map/([\w\-]+)\.md\)", index.read_text(encoding="utf-8"))
    files = {p.stem: p for p in feature_dir.glob("*.md")}
    ordered = [files[name] for name in order if name in files]
    ordered += sorted(p for name, p in files.items() if name not in order)
    features = []
    for path in ordered:
        match = _VERIFY_BLOCK.search(path.read_text(encoding="utf-8"))
        if match is None:
            raise ValueError(f"{path}: no ```json verify block")
        data = json.loads(match.group(1))
        features.append(
            Feature(
                id=data["id"],
                doc=path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path),
                paths=list(data.get("paths", [])),
                tests=list(data.get("tests", [])),
                smoke=list(data.get("smoke", [])),
                ui=list(data.get("ui", [])),
                manual=list(data.get("manual", [])),
            )
        )
    return features


def matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern)


def map_files(files: list[str], features: list[Feature]) -> tuple[list[Feature], list[str]]:
    """Features claiming any of ``files``, and the files no feature claims."""
    hit: list[Feature] = []
    claimed: set[str] = set()
    for feature in features:
        mine = [f for f in files if any(matches(f, p) for p in feature.paths)]
        # A change to the feature's own doc or tests also re-verifies it.
        mine += [f for f in files if f == feature.doc or f in feature.tests]
        if mine:
            hit.append(feature)
            claimed.update(mine)
    return hit, [f for f in files if f not in claimed]


# ── git ──────────────────────────────────────────────────────────────────────


def _git(*args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def changed_files(base: str) -> list[str]:
    """Committed changes since the merge-base with ``base``, plus the working tree."""
    files: list[str] = []
    merge_base = _git("merge-base", base, "HEAD")
    if merge_base:
        files += _git("diff", "--name-only", merge_base, "HEAD").splitlines()
    files += _git("diff", "--name-only", "HEAD").splitlines()
    files += _git("ls-files", "--others", "--exclude-standard").splitlines()
    return sorted({f for f in files if f})


def git_context(base: str) -> dict[str, Any]:
    return {
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "base": base,
        "dirty": bool(_git("status", "--porcelain")),
    }


# ── running ──────────────────────────────────────────────────────────────────


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(
            lambda m: (m.group(1) if m.groups() else "") + "[REDACTED]", text
        )
    return text


def substitute(value: str, out: Path) -> str:
    return value.replace("{py}", sys.executable).replace("{out}", out.as_posix())


@dataclass
class RunResult:
    exit_code: int | None
    output: str
    duration_s: float
    error: str = ""


def run_command(cmd: list[str], timeout: int) -> RunResult:
    started = time.monotonic()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "COLUMNS": "200"}
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        return RunResult(None, "", time.monotonic() - started, f"not found: {exc.filename}")
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout if isinstance(exc.stdout, str) else ""
        return RunResult(None, partial, time.monotonic() - started, f"timed out after {timeout}s")
    return RunResult(proc.returncode, proc.stdout + proc.stderr, time.monotonic() - started)


class Runner:
    def __init__(self, out: Path, *, ui: bool, timeout: int) -> None:
        self.out = out
        self.logs = out / "logs"
        self.ui = ui
        self.timeout = timeout
        self.checks: list[Check] = []
        self._tested: dict[str, str] = {}  # test file -> check id
        self._ui_done: dict[str, str] = {}  # fixture -> check id

    # -- helpers ---------------------------------------------------------------

    def _write_log(self, check_id: str, cmd: list[str], result: RunResult) -> str:
        self.logs.mkdir(parents=True, exist_ok=True)
        path = self.logs / f"{check_id}.log"
        header = f"$ {' '.join(cmd)}\n# exit={result.exit_code} duration={result.duration_s:.1f}s\n"
        if result.error:
            header += f"# error: {result.error}\n"
        path.write_text(redact(header + result.output), encoding="utf-8", newline="\n")
        return path.relative_to(self.out).as_posix()

    def _add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    def _next_id(self, kind: str) -> str:
        n = sum(1 for c in self.checks if c.kind == kind) + 1
        return f"{kind}-{n:02d}"

    # -- check kinds -----------------------------------------------------------

    def gate(self, name: str, cmd: list[str]) -> Check:
        check_id = self._next_id("gate")
        result = run_command(cmd, self.timeout)
        if result.exit_code is None:
            status, reason = BLOCKED, result.error
        else:
            status = PASS if result.exit_code == 0 else FAIL
            reason = "" if status == PASS else f"exit {result.exit_code}"
        return self._add(
            Check(check_id, "gate", name, status, ["*"], reason, cmd, result.exit_code, 0,
                  round(result.duration_s, 1), self._write_log(check_id, cmd, result))
        )

    def tests(self, feature: Feature) -> list[Check]:
        made: list[Check] = []
        missing = [t for t in feature.tests if not (ROOT / t).is_file()]
        if missing:
            made.append(self._add(Check(
                self._next_id("tests"), "tests", f"{feature.id}: missing test files",
                FAIL, [feature.id], f"listed in the feature map but absent: {missing}")))
        todo = [t for t in feature.tests if t not in self._tested and t not in missing]
        for t in feature.tests:
            if t in self._tested:
                # Already ran for an earlier feature: credit this feature too.
                for c in self.checks:
                    if c.id == self._tested[t] and feature.id not in c.features:
                        c.features.append(feature.id)
        if not todo:
            return made
        check_id = self._next_id("tests")
        junit = self.logs / f"{check_id}.junit.xml"
        self.logs.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
               f"--junitxml={junit}", *todo]
        result = run_command(cmd, self.timeout)
        counts = parse_junit(junit)
        status, reason = classify_pytest(result, counts)
        check = self._add(Check(
            check_id, "tests", f"{feature.id}: pytest ({len(todo)} files)", status,
            [feature.id], reason, cmd, result.exit_code, 0, round(result.duration_s, 1),
            self._write_log(check_id, cmd, result),
            [junit.relative_to(self.out).as_posix()] if junit.exists() else [],
            {"counts": counts, "files": todo},
        ))
        made.append(check)
        for t in todo:
            self._tested[t] = check_id
        if counts.get("skipped"):
            made.append(self._add(Check(
                self._next_id("skipped-tests"), "skipped-tests",
                f"{feature.id}: {counts['skipped']} skipped test(s)", NOT_RUN, [feature.id],
                "; ".join(counts.get("skip_reasons", [])) or "skipped by pytest",
                details={"of": check_id},
            )))
        return made

    def smoke(self, feature: Feature, spec: dict[str, Any]) -> Check:
        check_id = self._next_id("smoke")
        cmd = [substitute(str(part), self.out) for part in spec["cmd"]]
        result = run_command(cmd, int(spec.get("timeout", self.timeout)))
        status, reason, artifacts = evaluate_smoke(spec, result, self.out)
        return self._add(Check(
            check_id, "smoke", f"{feature.id}: {spec['name']}", status, [feature.id], reason,
            cmd, result.exit_code, int(spec.get("expect_exit", 0)), round(result.duration_s, 1),
            self._write_log(check_id, cmd, result), artifacts,
        ))

    def ui_check(self, feature: Feature, fixture: str) -> Check:
        if fixture in self._ui_done:
            for c in self.checks:
                if c.id == self._ui_done[fixture] and feature.id not in c.features:
                    c.features.append(feature.id)
            return next(c for c in self.checks if c.id == self._ui_done[fixture])
        check_id = self._next_id("ui")
        if not self.ui:
            check = self._add(Check(check_id, "ui", f"{feature.id}: browser check {fixture}",
                                    NOT_RUN, [feature.id], "disabled with --no-ui"))
            self._ui_done[fixture] = check_id
            return check
        cmd = [sys.executable, str(ROOT / "scripts" / "verify_ui.py"), "--fixture", fixture,
               "--out", self.out.as_posix()]
        result = run_command(cmd, self.timeout)
        status = {0: PASS, 1: FAIL, 2: BLOCKED}.get(
            result.exit_code if result.exit_code is not None else -1, BLOCKED
        )
        reason = result.error or ("" if status == PASS else _last_line(result.output))
        artifacts = [a for a in (f"ui-{fixture}.png", f"ui-{fixture}.json")
                     if (self.out / a).exists()]
        check = self._add(Check(
            check_id, "ui", f"{feature.id}: browser check {fixture}", status, [feature.id],
            reason, cmd, result.exit_code, 0, round(result.duration_s, 1),
            self._write_log(check_id, cmd, result), artifacts,
        ))
        self._ui_done[fixture] = check_id
        return check

    def manual(self, feature: Feature, text: str) -> Check:
        return self._add(Check(self._next_id("manual"), "manual", f"{feature.id}: {text}",
                               NOT_RUN, [feature.id], "manual: needs a human (and is not "
                               "something an agent may run unattended)"))


def _last_line(text: str) -> str:
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return lines[-1][:300] if lines else ""


def parse_junit(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return {}
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    counts: dict[str, Any] = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in suites:
        for key in ("tests", "failures", "errors", "skipped"):
            counts[key] += int(suite.get(key, 0))
    counts["skip_reasons"] = sorted({
        (skip.get("message") or "").strip()[:200]
        for skip in root.iter("skipped")
    } - {""})
    return counts


def classify_pytest(result: RunResult, counts: dict[str, Any]) -> tuple[str, str]:
    """Map a pytest run to a status. Skips are reported separately, never as PASS."""
    if result.exit_code is None:
        return BLOCKED, result.error
    if result.exit_code == 0:
        ran = counts.get("tests", 0) - counts.get("skipped", 0)
        if counts and ran <= 0:
            return NOT_RUN, "every collected test was skipped"
        return PASS, ""
    if result.exit_code == 5:
        return NOT_RUN, "pytest collected no tests"
    if result.exit_code in (3, 4):
        detail = _last_line(result.output)
        return BLOCKED, f"pytest could not run (exit {result.exit_code}): {detail}"
    if result.exit_code == 1 and "No module named pytest" in result.output:
        return BLOCKED, "pytest is not installed"
    return FAIL, (
        f"{counts.get('failures', '?')} failed, {counts.get('errors', '?')} errors"
        if counts else _last_line(result.output)
    )


def evaluate_smoke(
    spec: dict[str, Any], result: RunResult, out: Path
) -> tuple[str, str, list[str]]:
    if result.exit_code is None:
        return BLOCKED, result.error, []
    problems = []
    expected = int(spec.get("expect_exit", 0))
    if result.exit_code != expected:
        problems.append(f"exit {result.exit_code}, expected {expected}")
    needle = spec.get("expect_output")
    if needle and needle not in result.output:
        problems.append(f"output lacks {needle!r}")
    artifacts = []
    for raw in spec.get("expect_files", []):
        path = Path(substitute(raw, out))
        if path.exists():
            try:
                artifacts.append(path.relative_to(out).as_posix())
            except ValueError:
                artifacts.append(path.as_posix())
        else:
            problems.append(f"missing file {raw}")
    return (FAIL, "; ".join(problems), artifacts) if problems else (PASS, "", artifacts)


# ── orchestration ────────────────────────────────────────────────────────────


def worst(statuses: list[str]) -> str:
    return max(statuses, key=lambda s: _SEVERITY[s]) if statuses else NOT_RUN


def feature_summary(feature: Feature, checks: list[Check]) -> dict[str, Any]:
    mine = [c for c in checks if feature.id in c.features or "*" in c.features]
    automated = [c.status for c in mine if c.kind not in ("manual", "skipped-tests")]
    not_run = [c for c in mine if c.status == NOT_RUN]
    return {
        "feature": feature.id,
        "doc": feature.doc,
        # PASS only when every automated check ran and passed.
        "status": worst(automated) if automated else NOT_RUN,
        "checks": [c.id for c in mine],
        "not_run": [c.name for c in not_run],
    }


def exit_code(checks: list[Check]) -> int:
    statuses = {c.status for c in checks}
    if FAIL in statuses:
        return 1
    if BLOCKED in statuses:
        return 2
    return 0


def render_markdown(report: dict[str, Any]) -> str:
    ctx = report["context"]
    totals = report["totals"]
    lines = [
        "# Verification report",
        "",
        f"- Commit: `{ctx['commit'][:12]}` on `{ctx['branch']}`"
        f"{' (uncommitted changes)' if ctx['dirty'] else ''}, base `{ctx['base']}`",
        f"- Mode: {report['mode']} · Python {ctx['python']} · {ctx['platform']}",
        f"- Started: {report['started']} · Result: **exit {report['exit_code']}**",
        "- Totals: " + ", ".join(f"{s} {totals[s]}" for s in STATUSES),
        "",
        "## Features",
        "",
        "| Feature | Status | Not run |",
        "|---|---|---|",
    ]
    for f in report["features"]:
        lines.append(f"| {f['feature']} (`{f['doc']}`) | {f['status']} | {len(f['not_run'])} |")
    lines += ["", "## Checks", "", "| ID | Status | Check | Exit | Evidence | Reason |",
              "|---|---|---|---|---|---|"]
    for c in report["checks"]:
        evidence = ", ".join(x for x in [c["log"], *c["artifacts"]] if x)
        exit_text = "" if c["exit_code"] is None else (
            f"{c['exit_code']}" + (f" (want {c['expected_exit']})"
                                   if c["expected_exit"] not in (None, c["exit_code"]) else "")
        )
        lines.append(
            f"| {c['id']} | {c['status']} | {c['name']} | {exit_text} | {evidence} | "
            f"{c['reason'].replace('|', '/')} |"
        )
    if report["unmapped"]:
        lines += ["", "## Changed files no feature claims", ""]
        lines += [f"- `{f}`" for f in report["unmapped"]]
    lines += ["", "PASS = ran and held · FAIL = ran and broke · BLOCKED = could not run · "
              "NOT RUN = deliberately not executed. NOT RUN is never counted as PASS.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="main", help="branch to diff against (default: main)")
    parser.add_argument("--all", action="store_true", help="verify every feature")
    parser.add_argument("--feature", action="append", default=[], help="verify this feature id")
    parser.add_argument("--files", nargs="+", default=None, help="treat these as the change")
    parser.add_argument("--no-ui", action="store_true", help="skip browser checks (NOT RUN)")
    parser.add_argument("--no-gates", action="store_true", help="skip ruff/mypy (NOT RUN)")
    parser.add_argument("--list", action="store_true", help="print the mapping and exit")
    parser.add_argument("--timeout", type=int, default=900, help="per-command timeout (s)")
    parser.add_argument("--out", type=Path, default=None, help="evidence directory")
    args = parser.parse_args(argv)

    features = load_features()
    by_id = {f.id: f for f in features}
    unknown = [f for f in args.feature if f not in by_id]
    if unknown:
        parser.error(f"unknown feature(s) {unknown}; known: {sorted(by_id)}")

    if args.all:
        mode, files, selected, unmapped = "all", [], features, []
    elif args.feature:
        mode, files, unmapped = "feature", [], []
        selected = [f for f in features if f.id in args.feature]
    else:
        mode = "files" if args.files else "changed"
        files = sorted(args.files) if args.files else changed_files(args.base)
        selected, unmapped = map_files(files, features)

    if args.list:
        print(json.dumps({"changed": files, "features": [f.id for f in selected],
                          "unmapped": unmapped}, indent=2))
        return 0

    sha = (_git("rev-parse", "--short", "HEAD") or "nogit")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (args.out or ROOT / "verify-out") / f"{stamp}-{sha}"
    out.mkdir(parents=True, exist_ok=True)
    runner = Runner(out, ui=not args.no_ui, timeout=args.timeout)

    if mode in ("all", "feature"):
        python_changed = True
    else:
        python_changed = any(f.endswith(".py") or f == "pyproject.toml" for f in files)
    if selected and python_changed:
        if args.no_gates:
            runner._add(Check("gate-01", "gate", "ruff + mypy", NOT_RUN, ["*"],
                              "disabled with --no-gates"))
        else:
            ruff = shutil.which("ruff", path=str(Path(sys.executable).parent)) or "ruff"
            mypy = shutil.which("mypy", path=str(Path(sys.executable).parent)) or "mypy"
            runner.gate("ruff check", [ruff, "check", "."])
            runner.gate("mypy (strict)", [mypy])

    for feature in selected:
        print(f"[verify] {feature.id}", flush=True)
        runner.tests(feature)
        for spec in feature.smoke:
            runner.smoke(feature, spec)
        for fixture in feature.ui:
            runner.ui_check(feature, fixture)
        for item in feature.manual:
            runner.manual(feature, item)

    checks = runner.checks
    report = {
        "schema": 1,
        "started": stamp,
        "mode": mode,
        "context": {**git_context(args.base), "python": platform.python_version(),
                    "platform": platform.platform()},
        "changed": files,
        "unmapped": unmapped,
        "features": [feature_summary(f, checks) for f in selected],
        "checks": [asdict(c) for c in checks],
        "totals": {s: sum(1 for c in checks if c.status == s) for s in STATUSES},
        "exit_code": exit_code(checks),
    }
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8", newline="\n")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")

    for c in checks:
        print(f"  {c.status:8} {c.id:16} {c.name}" + (f"  -- {c.reason}" if c.reason else ""))
    if not selected:
        print("  no feature is affected by this change; nothing to verify")
    print(f"[verify] totals: {report['totals']}  exit={report['exit_code']}")
    print(f"[verify] evidence: {out}")
    return int(report["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
