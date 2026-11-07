# AIBOM Inspector: working rules for Claude Code

A static, evidence-backed AIBOM scanner (Python 3.10+, FastAPI, one-file web
UI). The product's contract is **no evidence, no claim**, and the same contract
applies to work done on it: a task is finished when its checks have run and
left evidence, not when it looks finished.

## Before changing anything

- Read the affected feature file in [docs/feature-map/](docs/feature-map.md):
  entry points, error and boundary paths, and what usually breaks.
  `python scripts/verify.py --list --files <paths>` tells you which file.
- Read the code and tests you are about to change. Reproduce a bug before
  fixing it.
- Architecture and the dependency-map edge rules: [docs/architecture.md](docs/architecture.md).
- Scanned code is read, never imported or executed. Keep it that way: no
  `exec`, `import` of target code, or model loading in collectors and detectors.

## While implementing

- Test first for behavior changes. Watch the new test fail for the right
  reason, and include a negative case (what must *not* be detected or linked).
- Every entity, edge, and finding needs `Evidence` pointing at a real
  `file:line`. Never use placeholders such as `<inferred>`.
- No new runtime dependencies without asking. Dev-only tools go in the `dev`
  extra, or in CI only (Playwright is CI-only).
- When a module is added under `src/aibom/` or `web/`, add it to a feature file.
  `tests/test_feature_map.py` fails otherwise.
- On Windows, write files with LF (`newline="\n"`), and check
  `git ls-files --eol` before committing.

## After every change: verify

Run the [verify skill](.claude/skills/verify/SKILL.md) (`/verify`), or
directly:

```bash
.venv/Scripts/python.exe scripts/verify.py          # Windows; .venv/bin/python elsewhere
```

It runs ruff, mypy, the affected features' tests, CLI smoke commands, and
headless-browser checks. Each check is reported as **PASS / FAIL / BLOCKED /
NOT RUN**, and evidence goes to `verify-out/<run>/` (gitignored).

The completion report must include:

- the command, its exit code, and the evidence path (`verify-out/<run>/report.md`);
- a per-feature status table;
- every BLOCKED and NOT RUN item, with the reason and what a human must do;
- for UI changes, which screenshot you looked at and what you saw.

Never present a check that did not run as passed. A skipped test is NOT RUN,
and "should work" is not a status. If you loosened a test expectation, say so
and why.

## Quality gates (same as CI)

```bash
.venv/Scripts/ruff.exe check .
.venv/Scripts/mypy.exe            # strict, src/aibom
.venv/Scripts/python.exe -m pytest
```

## Requires explicit human approval: ask every time

- Security-relevant code or settings: the clone URL allowlist and SSRF guards
  (`server/clone.py`), CORS defaults, `safeio.py` limits, the credential-key
  rejection in `agent_security/manifest.py`, and lint suppressions
  (`noqa`, `# type: ignore`) on security findings.
- Secrets: never print, log, commit, or paste tokens or keys, including in
  test fixtures (use obviously fake values).
- Outward-facing actions: `git push`, opening or merging PRs, tags and
  releases, `release.yml` / `pages.yml` dispatches, Docker pushes, and
  render.com or Pages deploys.
- Network calls that send repository data to third parties: `--resolve`,
  `--vulns`, live clones, benchmark checkouts, and regenerating published
  `benchmark/reports/`.
- Destructive operations: force push, `reset --hard`, deleting fixtures,
  examples, or reports.

## Failure to skill

When a mistake escapes or repeats, turn it into a regression test first. Then
add a mechanical check (test, lint, or feature-map rule). Then update the
feature file's "what usually breaks". Change the verify skill only when none of
those can hold the lesson, and add an eval case when you do
(`.claude/skills/verify/evals/cases.json`).
