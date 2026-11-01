# Agent Identity & Privilege Drift (P0)

> **The AI-BOM stays the same. The agent's effective capabilities change.**

This extension links what the AI-BOM already knows — an agent, the tools it
binds, and what those tools do — to an *explicitly declared* cloud identity and
its identity policy. Comparing two revisions then shows when an agent gains a
**potential** capability even though no model, package, prompt or tool changed.

Design source: [AIBOM_Inspector_Agent_Identity_Privilege_Drift_Design.md](AIBOM_Inspector_Agent_Identity_Privilege_Drift_Design.md).
This page documents what is **implemented and tested**; anything not listed here
is not supported.

## Try it (offline, ~2 s)

```bash
aibom demo --scenario agent-privilege-drift                    # Baseline -> Candidate -> Fixed
aibom demo --scenario agent-privilege-drift --output-dir out/  # also save every JSON artifact

aibom scan examples/agent-privilege-drift/baseline --identity-manifest aibom-identity.yaml -o inv.json
aibom diff examples/agent-privilege-drift/baseline examples/agent-privilege-drift/candidate \
  --agent-privileges -o drift.json --fail-on high             # exits 1
```

The scenario (`examples/agent-privilege-drift/`) has three revisions with an
identical `app/agent.py`, `requirements.txt` and `aibom-identity.yaml`. Only
`policy/review-role.json` differs:

| Stage | Role policy | Result (measured with the bundled scenario) |
|---|---|---|
| baseline | `s3:GetObject` | `read_asset -> s3:GetObject` potentially allowed; `publish_review -> s3:PutObject` no matching allow |
| candidate | `+ s3:PutObject, s3:DeleteObject` | AI-BOM unchanged; **`permission_scope_expanded`** (high) for PutObject via `publish_review`; `identity_permission_expanded` (medium) for DeleteObject, because the only tool that deletes (`purge_asset`) is **not bound** |
| fixed | back to `s3:GetObject` | `potential_privilege_removed` ×2; baseline vs fixed: 0 changes, 0 unknowns |

## What is supported

| Layer | Supported in P0 | Everything else |
|---|---|---|
| Agent definition | Python OpenAI Agents SDK `x = Agent(...)` (module or function scope) in production sources | Unknown / not reported |
| Tool binding | Explicit `tools=[...]` resolved by the existing binding analysis (same tool component IDs as the inventory, incl. imported tools and `TOOLS` lists) | `tool_definition_unresolved` |
| Tool → operation | `boto3.client("<svc>")` receiver + mapped method in the tool body (S3, DynamoDB, Secrets Manager, a few IAM methods; see `operations.ACTIONS`), or an explicit `tools:` entry in the manifest | Helpers, `boto3.resource`, sessions, dynamic dispatch: not seen |
| Agent → identity | **Only** the identity manifest, matched by `<file>:<variable>` | `identity_unmapped`; never inferred from names |
| Policy | AWS identity policy JSON: `Effect`, `Action`, `Resource`, `Sid`; `*`/`?` wildcards; Deny wins | `NotAction`, `NotResource`, `Condition`, policy variables, `Principal` → **unknown** |

## Verdicts (per agent → tool → action → resource)

| Verdict | Meaning |
|---|---|
| `potentially_allowed` | An Allow in the **supplied** identity policies matches and no supplied Deny does. Always carries `identity-policy-only`, `runtime-identity-unverified`; `proven` is always `false`. |
| `explicitly_denied` | A fully evaluated Deny matches. |
| `no_matching_allow_in_supplied_policies` | No supplied Allow matches. **Not** "cannot happen": other policies may exist. |
| `unknown` | Missing/unparsable policy, unmapped/undefined identity, unevaluated element that could apply, or a resource that only partially overlaps. Always with a reason. |

## Drift types

| Type | When | Gates `--fail-on` |
|---|---|---|
| `permission_scope_expanded` | Same path, verdict `no_match`/`denied` → `potentially_allowed` | yes |
| `privilege_path_added` | New agent/tool/operation path that is potentially allowed | yes |
| `privileged_identity_binding_added` | Path now potentially allowed through a different identity | yes |
| `identity_permission_expanded` | New grant no analyzed bound tool uses (severity capped at medium; does **not** claim the agent can act) | yes |
| `review_required` | `unknown` ↔ `potentially_allowed`; certainty `unknown`, severity capped | **no** |
| `potential_privilege_removed` | Path or grant no longer potentially allowed | no |

Severity and certainty are separate axes. Severity = operation hazard
(`list` low, `read` medium, `write`/`delete`/`secrets_read` high, `admin`
critical), +1 when the agent's instructions are proven to reach untrusted input
(existing prompt-flow analysis). Comparison keys are
`agent|tool|action|resource` — line numbers and JSON formatting never cause drift.
Every supported addition carries `remediation` (`why_it_matters`, conditions,
recommended actions, `retest_command`). Fixes are suggested, never applied.

## Identity manifest (`aibom-identity.yaml`)

```yaml
schema_version: 1
agents:
  - agent_ref: "agent:reviewer"
    source: "app/agent.py:reviewer"       # <file>:<assigned variable>
    identity_ref: "aws:role/demo-review-role"
identities:
  - id: "aws:role/demo-review-role"
    provider: aws
    policies: ["policy/review-role.json"] # workspace-relative
    provenance: explicit_manifest
tools:                                    # optional explicit tool -> action mapping
  - source: "app/agent.py:sync_assets"
    actions: ["s3:PutObject"]
    resources: ["arn:aws:s3:::demo-assets/*"]
```

Input safety: strict YAML subset parser (no anchors, aliases, tags, block
scalars or multi-document streams; JSON also accepted), unknown keys rejected,
256 KiB manifest / 1 MiB policy limits, every referenced path must resolve
(symlinks included) inside the scan target — `..`, absolute paths, drive
letters and URLs are input errors (exit code 2). Credential-looking keys
(`secret`, `token`, `access_key`, …) are rejected without echoing the value.
Nothing in the scanned repository is imported or executed, and no cloud API is
called.

## Output

* `aibom scan … --identity-manifest M -o inv.json` adds one top-level key,
  `agent_security`; every existing inventory key is unchanged.
* `aibom diff … --agent-privileges -o drift.json` adds `agent_privileges`.
* CycloneDX, SARIF and the HTML report are unchanged.
* The report (`schema_version: "1.0"`) contains `scope` (what was and was not
  evaluated), `agents`, `identities`, `policies`, `permissions`, `operations`,
  `capability_paths`, `unknowns`, and an evidence graph (`nodes`/`edges`:
  `agent`, `tool`, `operation`, `identity`, `policy`, `permission`, `resource`;
  `BINDS_TOOL`, `REACHES_OPERATION`, `RUNS_AS`, `ATTACHES_POLICY`,
  `ALLOWS_ACTION`, `DENIES_ACTION`, `TARGETS_RESOURCE`), each with
  `source_type` and `resolution_status`.

## Non-goals and limits

* Not an AWS authorization engine: no SCPs, permission boundaries, session
  policies, resource-based policies, KMS key policies, trust policies or
  `Condition` evaluation; `sts:AssumeRole` / `iam:PassRole` are never treated as
  a successful delegation.
* Does not decide what an LLM will do, nor whether prompt injection succeeds.
* Source code alone never establishes the runtime principal.
* Agents are never labeled "shadow": `management_status` is `unknown` (no
  approved-agent registry in P0).
* Agent-to-agent delegation / handoffs, MCP capability graphs, JS/TS, Graph UI
  and SARIF output for privilege drift are P1; Azure/GCP/OAuth and runtime
  observation are P2. None of these are implemented.
* Evaluation so far is the bundled scenario plus 36 unit/CLI tests
  (`tests/test_agent_security.py`); no precision/recall on external
  repositories has been measured yet.

## Arsenal abstract (draft)

> **Beyond AI-BOM: Detecting Agent Privilege Drift and Hidden Capability Expansion.**
> SBOM and AI-BOM inventories describe which components exist; they do not show
> how an AI agent's permitted actions change when identities or policies change.
> AIBOM Inspector links agents, their explicit tool bindings, the cloud
> operations those tools perform, declared identity mappings and bounded
> identity-policy evidence, and reports capability drift with evidence — even
> when the component inventory is byte-for-byte identical.

Demo script (≈5 min): `aibom scan --demo` (discovery) → `aibom demo --scenario
agent-privilege-drift` (baseline read-only → policy-only change with BOM
unchanged → `permission_scope_expanded` with policy pointer and tool line →
fix → retest shows 0 additions) → limits table above.
