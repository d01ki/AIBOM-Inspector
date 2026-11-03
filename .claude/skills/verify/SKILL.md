---
name: verify
description: Verify a change to AIBOM Inspector with executed checks and evidence, then report each check as PASS / FAIL / BLOCKED / NOT RUN. Use after implementing or fixing anything in this repo, before saying a task is done, committing, or opening a PR, and whenever asked to "verify", "check it works", or "prove it".
when_to_use: After any code, fixture, UI or feature-map change; before a completion report; for a full regression sweep use "/verify --all".
argument-hint: "[--all | --feature ID | --files PATH...] [--no-ui]"
---

# Verify

A change is done when its checks have **run** and left **evidence**, not when
the code looks right, compiles, or an agent says it is finished. This skill
turns "I implemented X" into a report a reviewer can audit.

The source of truth is the [feature map](../../../docs/feature-map.md): one file
per feature, listing its source globs, tests, smoke commands, browser
fixtures, and manual checks. `scripts/verify.py` executes that map.

## Steps

1. **Find the affected features.**
   `python scripts/verify.py --list` (or `--files <paths>`) prints the
   changed files, the features that claim them, and the files no feature
   claims. Unmapped `src/aibom/**` or `web/**` files are a defect: add them to
   a feature file. `tests/test_feature_map.py` fails until you do.
2. **Read each affected feature file** in `docs/feature-map/`: its normal,
   error, and boundary paths, and its "what usually breaks" notes. If your
   change adds a path the file does not mention, update the file now.
3. **Check the existing tests cover the change.** Open the feature's listed
   tests. If the changed behavior has no test, write one first and watch it
   fail for the right reason before trusting it. A test that would also pass
   on the old code proves nothing.
4. **Run the checks.**
   `python scripts/verify.py $ARGUMENTS`
   With no arguments it verifies everything changed since `main`, including
   uncommitted and untracked files. Use the project venv's Python
   (`.venv/Scripts/python.exe` on Windows, `.venv/bin/python` elsewhere).
5. **Exercise the real thing.** The script already drives the CLI (smoke) and
   a headless browser against the real FastAPI app (UI). For a behavior the
   map does not cover yet, run it by hand (CLI command, `TestClient` request,
   or `scripts/verify_ui.py --fixture …`), then add it to the feature file so
   the next run does it automatically.
6. **Collect evidence.** Everything lands in
   `verify-out/<timestamp>-<sha>/`: `report.md`, `report.json`, `logs/*.log`
   (redacted), junit XML, screenshots, and generated artifacts. **Look at the
   screenshot.** A PASS from the DOM checks does not prove the layout is
   readable.
7. **Report** using the template below.

## The four states

| State | Meaning | Counts as done? |
|---|---|---|
| PASS | ran, and every expectation held | yes |
| FAIL | ran, and an expectation did not hold | no. Fix the root cause and rerun |
| BLOCKED | could not run (tool, browser, or network missing, or a timeout) | no. Say what is missing |
| NOT RUN | deliberately not executed (manual item, `--no-ui`, skipped tests) | no. List it as unverified |

Rules that are never bent:

- **Never report a check you did not run as PASS.** Not in prose, not in a
  table, not as "should pass". A skipped test is NOT RUN.
- Do not edit a test or loosen an expectation to turn FAIL into PASS unless
  the expectation itself was wrong. Then say so explicitly, with the reason.
- Re-run after every fix. A PASS from before the last edit is stale.
- Rerunning the same failing command while hoping it changes is not
  debugging. Find the cause.

## Report template

```markdown
## Verification
Commit `<sha>` (+ uncommitted: yes/no) · `python scripts/verify.py <args>` · exit <n>
Evidence: verify-out/<run>/report.md

| Feature | Status | Notes |
|---|---|---|
| dependency-map | PASS | 5 test files, 2 smoke, 2 browser runs |

Not verified (NOT RUN / BLOCKED):
- <check>: <why>, <what a human needs to do>

Screenshots reviewed: <file>: <one-line observation>
```

## Needs a human. Never run these unattended

Ask first, every time, even if a similar action was approved earlier:

- Security settings, authentication and authorization code, CORS defaults,
  and the clone URL allowlist (`src/aibom/server/clone.py`).
- Anything touching secrets or credentials: never print, log, or commit them.
  `verify.py` redacts its logs, but do not rely on that.
- Releases, tags, GitHub Pages or render.com deploys, `release.yml` and
  `pages.yml` dispatches, Docker pushes.
- Network calls that send repository data to third parties (`--resolve`,
  `--vulns`, live clones, benchmark checkouts). These are the map's manual
  items.
- Destructive git or file operations (force push, `reset --hard`, deleting
  fixtures or published benchmark reports).

## Failure to skill

When a bug escapes, or the same mistake happens twice, convert it into a check
rather than a reminder:

1. Reproduce it with a failing test in the feature's test list (regression
   test first).
2. If the rule can be decided mechanically, enforce it in a test, ruff, or
   `tests/test_feature_map.py`, not in prose. For example, edge evidence must
   cite a real file (`tests/test_linking.py::test_colocation_edges_cite_a_real_line`).
3. Add the failure to the feature file's "Known gaps / what usually breaks".
4. Only if neither code nor the map can hold the lesson, improve **this**
   skill. Prefer editing it over adding a new skill. Then add a case to
   `evals/cases.json` and keep `tests/test_verify_skill.py` green.

## Files

- `evals/cases.json`: scenarios this skill must handle, with the expected
  feature mapping and the behaviors that count as a failure.
- `scripts/verify.py`, `scripts/verify_ui.py`: the executors.
- `docs/feature-map/*.md`: what to verify per feature.
