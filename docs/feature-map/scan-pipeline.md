# Scan pipeline

## Overview

`run_scan` (`src/aibom/service.py`) is the one pipeline the CLI, the API, and
the UI share. It collects files, parses Python and JS/TS once into a
`ProjectIndex`, runs the detectors, then the manifest, lockfile, and component
linkers, normalizes the inventory, applies the production policy view, and
evaluates the deterministic risk rules and score. It reads the scanned code but
**never imports or executes it**.

## Entry points

- CLI: `aibom scan <path|url> [-o inv.json] [--fail-on SEV] [--min-confidence F]
  [--disable-detector ID] [--ignore-rule RULE] [--no-config]`; with no target on
  a TTY it shows a guided menu.
- API: `POST /api/scan` (via the cloner), `POST /api/demo`.
- Library: `aibom.service.run_scan(path, ...)`.

## Source

`src/aibom/service.py`, `cli.py`, `config.py`, `policy.py`, `inventory.py`,
`tools.py`, `exposure.py`, `impact.py`, `spdx.py`, `collectors/repo.py`,
`collectors/base.py`, `detectors/**`, `models/**`, `risk/**`.

## Depends on

Nothing upstream. Every other feature consumes its `ScanResult`.

## Normal paths

- Python and TS fixtures produce models, prompts, agents, tools, and services,
  each with `file:line` evidence.
- An untrusted source that reaches a system prompt produces an exposure path.
  A bound tool that reaches an operation produces an impact path.
- `aibom.toml` / `[tool.aibom]` in a *local* target supplies defaults, and
  explicit flags override them.

## Error paths

- Missing target: exit 2 with `error: target does not exist`.
- A file that fails to parse falls back to the legacy regex detector and is
  counted in `stats.parse_errors`.
- A URL target never contributes config, so a scanned third-party repo
  cannot silence its own findings.

## Boundaries

- Files over the size cap are skipped. Ignored directories (`node_modules`,
  `.venv`, …) are not walked.
- `--min-confidence 1.0` drops nearly everything, along with the dangling
  edges.
- Test, example, and docs contexts stay in the inventory but are excluded
  from findings and the graph.

## How to verify

| Check | Proves |
|---|---|
| detector, collector, and risk tests (listed below) | detection precision and recall on the fixtures, the rule mapping, and the score |
| `aibom scan tests/fixtures/vulnerable-ai-app -q -o …` | the end-to-end CLI writes an inventory (exit 0) |
| `aibom scan … --fail-on high` | the CI gate exits 1 on high findings |
| `aibom scan tests/fixtures/does-not-exist` | a clean error and exit 2, not a traceback |

## Expected results

Exit codes 0 / 1 / 2 as above. `inv.json` lists entities with
`source_evidence`, and `stats.files_scanned > 0`.

## Evidence

Command lines, exit codes, stdout and stderr logs, and `inv.json`.

## Known gaps / what usually breaks

- Precision regressions show up in `tests/test_precision.py` and
  `tests/test_corpus_regressions.py` before anywhere else.
- Reachability is bounded. `unknown` does not mean unreachable.

```json verify
{
  "id": "scan-pipeline",
  "paths": [
    "src/aibom/__init__.py",
    "src/aibom/py.typed",
    "src/aibom/service.py",
    "src/aibom/cli.py",
    "src/aibom/config.py",
    "src/aibom/policy.py",
    "src/aibom/inventory.py",
    "src/aibom/tools.py",
    "src/aibom/exposure.py",
    "src/aibom/impact.py",
    "src/aibom/spdx.py",
    "src/aibom/provenance.py",
    "src/aibom/collectors/__init__.py",
    "src/aibom/collectors/base.py",
    "src/aibom/collectors/repo.py",
    "src/aibom/detectors/**",
    "src/aibom/models/**",
    "src/aibom/risk/**",
    "tests/conftest.py",
    "tests/fixtures/vulnerable-ai-app/**",
    "tests/fixtures/vulnerable-ts-agent/**",
    "tests/fixtures/multi-language-agent/**"
  ],
  "tests": [
    "tests/test_cli.py",
    "tests/test_config.py",
    "tests/test_entities.py",
    "tests/test_repo_collector.py",
    "tests/test_python_ast_detectors.py",
    "tests/test_javascript_parser.py",
    "tests/test_javascript_prompt_flow.py",
    "tests/test_js_mcp_detection.py",
    "tests/test_js_model_catalog.py",
    "tests/test_prompt_flow.py",
    "tests/test_project_index.py",
    "tests/test_cross_file_python.py",
    "tests/test_cross_file_typescript.py",
    "tests/test_multi_language.py",
    "tests/test_tool_capabilities.py",
    "tests/test_exposure.py",
    "tests/test_impact.py",
    "tests/test_risk_rules.py",
    "tests/test_surface_rules.py",
    "tests/test_scoring_report.py",
    "tests/test_scan_stats.py",
    "tests/test_provenance.py",
    "tests/test_analysis_scope.py",
    "tests/test_precision.py",
    "tests/test_corpus_regressions.py"
  ],
  "smoke": [
    {
      "name": "scan vulnerable-ai-app",
      "cmd": ["{py}", "-m", "aibom.cli", "scan", "tests/fixtures/vulnerable-ai-app", "-q",
              "-o", "{out}/scan-inventory.json"],
      "expect_exit": 0,
      "expect_files": ["{out}/scan-inventory.json"]
    },
    {
      "name": "--fail-on high gates on findings",
      "cmd": ["{py}", "-m", "aibom.cli", "scan", "tests/fixtures/vulnerable-ai-app", "-q",
              "--fail-on", "high"],
      "expect_exit": 1
    },
    {
      "name": "missing target is a clean error",
      "cmd": ["{py}", "-m", "aibom.cli", "scan", "tests/fixtures/does-not-exist", "-q"],
      "expect_exit": 2,
      "expect_output": "target does not exist"
    }
  ],
  "ui": [],
  "manual": []
}
```
