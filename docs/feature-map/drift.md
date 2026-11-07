# Behavioral drift

## Overview

`aibom diff` scans two revisions independently and reports what changed in
behavior, not just in components. Its headline case: the component BOM is
identical, yet a new untrusted → privileged prompt → bound tool path appeared.
Paths are matched line-insensitively (prompt slot, then semantic key), so moved
code is not reported as remove/add noise.

## Entry points

- CLI: `aibom diff <baseline> <candidate> [--fail-on SEV] [-o drift.json]
  [--agent-privileges]`, and `aibom demo` (the bundled 5-step talk demo).
- API: `POST /api/diff` (two refs of one repo), `POST /api/diff/demo`.
- UI: the compare view and the hero demo buttons.

## Source

`src/aibom/drift.py`, `src/aibom/demo.py`, the CLI `diff` and `demo` commands,
and the fixtures `tests/fixtures/xfile-*`, `impact-demo*`, and
`examples/trust-boundary-drift`.

## Depends on

Scan pipeline (exposure and impact paths) and Exports (BOM comparison).

## Normal paths

The cross-file candidate adds a proven path (`routes/api.py:11 →
prompts/builder.py:8 → assistant/main.py:9 → tools/executor.py:16`), and
`--fail-on high` exits 1. Identical revisions exit 0.

## Error paths

A missing revision path is a clean error. An `unknown` evidence level never
gates `--fail-on`.

## Boundaries

Comparing a revision with itself produces no changes. A rename or a line move
is not a change. `potential` paths are capped at High.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_drift.py tests/test_drift_identical_bom.py` | the matching and gating rules |
| smoke: `diff xfile-py-baseline xfile-py-candidate --fail-on high` | the CLI gate fires (exit 1) |
| smoke: `diff baseline baseline --fail-on high` | no false drift (exit 0) |
| smoke: `aibom demo` | the offline talk demo still runs end to end |

## Expected results

The exit codes above, and the demo's last step reports the fix removed the
path.

## Evidence

Exit codes, the drift JSON, and the demo stdout log.

## Known gaps / what usually breaks

Fixture line numbers are asserted in the demo text. Editing a fixture usually
breaks the demo before anything else.

```json verify
{
  "id": "drift",
  "paths": [
    "src/aibom/drift.py",
    "src/aibom/demo.py",
    "src/aibom/cli.py",
    "tests/fixtures/xfile-*/**",
    "tests/fixtures/impact-demo*/**",
    "examples/trust-boundary-drift/**"
  ],
  "tests": [
    "tests/test_drift.py",
    "tests/test_drift_identical_bom.py"
  ],
  "smoke": [
    {
      "name": "diff gates a new cross-file path",
      "cmd": ["{py}", "-m", "aibom.cli", "diff", "tests/fixtures/xfile-py-baseline",
              "tests/fixtures/xfile-py-candidate", "-q", "--fail-on", "high",
              "-o", "{out}/drift.json"],
      "expect_exit": 1,
      "expect_files": ["{out}/drift.json"]
    },
    {
      "name": "identical revisions do not drift",
      "cmd": ["{py}", "-m", "aibom.cli", "diff", "tests/fixtures/xfile-py-baseline",
              "tests/fixtures/xfile-py-baseline", "-q", "--fail-on", "high"],
      "expect_exit": 0
    },
    {
      "name": "offline talk demo",
      "cmd": ["{py}", "-m", "aibom.cli", "demo"],
      "expect_exit": 0,
      "expect_output": "5/5"
    }
  ],
  "ui": [],
  "manual": []
}
```
