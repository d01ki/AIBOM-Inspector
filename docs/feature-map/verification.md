# Verification harness

## Overview

This is the tooling that decides whether a change is done: this feature map,
`scripts/verify.py` (change → features → checks → four-state report),
`scripts/verify_ui.py` (headless browser evidence), and the
[verify skill](../../.claude/skills/verify/SKILL.md) that tells an agent how
to use them. It is verified like any other feature, because a harness that
reports PASS for something it did not run is worse than no harness.

## Entry points

- `python scripts/verify.py [--all | --feature ID | --files F…] [--no-ui] [--list]`
- `python scripts/verify_ui.py --fixture NAME --out DIR`
- `/verify` in Claude Code.

## Source

`scripts/verify.py`, `scripts/verify_ui.py`, `.claude/skills/verify/**`,
`docs/feature-map.md`, `docs/feature-map/*.md`.

## Depends on

pytest, ruff, and mypy (dev extra), plus Playwright and Chromium for UI checks
(installed in the dev venv, not a project dependency).

## Normal paths

A changed file maps to its features, and only their checks run. Every check
records its command, exit code, duration, and a redacted log.

## Error paths

- A missing tool or browser yields BLOCKED, never PASS.
- A test file listed in the map but absent yields FAIL.
- A feature-map block that does not parse is an error at load.

## Boundaries

- A skipped test becomes a separate NOT RUN check.
- A run where every test was skipped is NOT RUN.
- A change that no feature claims is listed as "unmapped".
- Manual items are always NOT RUN.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_verify_script.py` | the status classification, mapping, redaction, and exit-code policy, including the "never PASS what did not run" cases |
| `pytest tests/test_feature_map.py` | every glob matches, every listed test exists, every shipped source file is mapped |
| `pytest tests/test_verify_skill.py` | the skill's frontmatter and its eval cases are well-formed and consistent with the script |

## Expected results

All three pass, and `python scripts/verify.py --list` maps
`src/aibom/graph.py` to `dependency-map`.

## Evidence

pytest output, plus a sample `verify-out/<run>/report.md`.

## Known gaps / what usually breaks

Glob mistakes in a new feature file. `test_feature_map.py` catches them.

```json verify
{
  "id": "verification",
  "paths": [
    "scripts/verify.py",
    "scripts/verify_ui.py",
    ".claude/skills/verify/**",
    "docs/feature-map.md",
    "docs/feature-map/*.md",
    "CLAUDE.md"
  ],
  "tests": [
    "tests/test_verify_script.py",
    "tests/test_feature_map.py",
    "tests/test_verify_skill.py"
  ],
  "smoke": [
    {
      "name": "change mapping resolves graph.py to dependency-map",
      "cmd": ["{py}", "scripts/verify.py", "--list", "--files", "src/aibom/graph.py"],
      "expect_exit": 0,
      "expect_output": "\"dependency-map\""
    }
  ],
  "ui": [],
  "manual": []
}
```
