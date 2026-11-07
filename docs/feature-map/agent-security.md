# Agent security (identity & privilege drift)

## Overview

This is an opt-in layer (`src/aibom/agent_security/`). It joins agents, their
bound tools, the boto3 operations those tools call, the identity the agent runs
as (from an explicit `aibom-identity.yaml`), and that identity's IAM policy. The
result is evidence-only capability paths with Allow/Deny/Unknown verdicts.
Drift between revisions is reported separately from the main inventory. It
never changes the inventory, findings, CycloneDX, or SARIF.
See [agent-privilege-drift.md](../agent-privilege-drift.md).

## Entry points

- CLI: `aibom scan <t> --identity-manifest m.yaml [--agent-registry r.yaml]`,
  `aibom diff a b --agent-privileges`,
  `aibom demo --scenario agent-privilege-drift|mcp-tool-exposure [--output-dir d]`.
- API: `POST /api/agent-drift/demo`, and the `agent_security` key of `/api/scan`.
- UI: the agent security graph and the drift tabs.

## Source

`src/aibom/agent_security/**`, `examples/agent-privilege-drift/**`,
`examples/mcp-tool-exposure/**`.

## Depends on

Scan pipeline (`ProjectIndex`, prompt-flow tool bindings).

## Normal paths

Baseline → Candidate adds a privileged capability path. Fixed removes it. MCP
tool filters are evaluated statically.

## Error paths

A manifest with unknown keys or credential-looking keys is rejected (`extra
keys forbidden`). A path outside the workspace or an oversized file raises
`InputError`. An unknown scenario name exits 2.

## Boundaries

Unsupported IAM elements produce `unknown`, not Allow. No manifest means no
identity edge (RUNS_AS is explicit only).

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_agent_security*.py` | the schema, IAM evaluator, MCP graph, drift, and SARIF |
| smoke: both `demo --scenario …` with `--output-dir` | the scenarios run offline and write every stage report |
| smoke: `demo --scenario nope` | a clean rejection (exit 2) |

## Expected results

Exit 0, with `summary.json` and every `*.agent-security.json` written.

## Evidence

The scenario output directory, plus exit codes and logs.

## Known gaps / what usually breaks

Only the AWS identity-policy subset is supported. Other clouds produce
`unknown`.

```json verify
{
  "id": "agent-security",
  "paths": [
    "src/aibom/agent_security/**",
    "examples/agent-privilege-drift/**",
    "examples/mcp-tool-exposure/**"
  ],
  "tests": [
    "tests/test_agent_security.py",
    "tests/test_agent_security_coverage.py",
    "tests/test_agent_security_mcp.py",
    "tests/test_agent_security_p1.py"
  ],
  "smoke": [
    {
      "name": "agent-privilege-drift scenario",
      "cmd": ["{py}", "-m", "aibom.cli", "demo", "--scenario", "agent-privilege-drift",
              "--output-dir", "{out}/agent-privilege-drift"],
      "expect_exit": 0,
      "expect_files": ["{out}/agent-privilege-drift/summary.json"]
    },
    {
      "name": "mcp-tool-exposure scenario",
      "cmd": ["{py}", "-m", "aibom.cli", "demo", "--scenario", "mcp-tool-exposure",
              "--output-dir", "{out}/mcp-tool-exposure"],
      "expect_exit": 0,
      "expect_files": ["{out}/mcp-tool-exposure/summary.json"]
    },
    {
      "name": "unknown scenario is rejected",
      "cmd": ["{py}", "-m", "aibom.cli", "demo", "--scenario", "nope"],
      "expect_exit": 2
    }
  ],
  "ui": [],
  "manual": []
}
```
