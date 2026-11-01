# Agent Identity & Privilege Drift (P0 + P1 subset)

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
aibom demo --scenario mcp-tool-exposure                        # MCP tool_filter removed

aibom scan examples/agent-privilege-drift/baseline --identity-manifest aibom-identity.yaml -o inv.json
aibom diff examples/agent-privilege-drift/baseline examples/agent-privilege-drift/candidate \
  --agent-privileges -o drift.json --fail-on high             # exits 1

# P1: SARIF for Code Scanning, and an operator-supplied approved-agent registry
aibom diff <baseline> <candidate> --agent-privileges --agent-sarif agents.sarif \
  --agent-registry approved_agents.yaml
aibom scan <dir> --agent-registry approved_agents.yaml -o inv.json
```

The scenario (`examples/agent-privilege-drift/`) has three revisions with an
identical `app/agent.py`, `requirements.txt` and `aibom-identity.yaml`. Only
`policy/review-role.json` differs:

| Stage | Role policy | Result (measured with the bundled scenario) |
|---|---|---|
| baseline | `s3:GetObject` | `read_asset -> s3:GetObject` potentially allowed; `publish_review -> s3:PutObject` no matching allow |
| candidate | `+ s3:PutObject, s3:DeleteObject` | AI-BOM unchanged; **`permission_scope_expanded`** (high) for PutObject via `publish_review`; `identity_permission_expanded` (medium) for DeleteObject, because the only tool that deletes (`purge_asset`) is **not bound** |
| fixed | back to `s3:GetObject` | `potential_privilege_removed` ×2; baseline vs fixed: 0 changes, 0 unknowns |

### Second scenario: `mcp-tool-exposure`

`examples/mcp-tool-exposure/` keeps the MCP server, packages, identity
manifest and both role policies identical. The agent's own role denies `s3:*`;
the **MCP server process** runs as a separate role that may read and delete
assets. Only the agent's `tool_filter` changes:

| Stage | `MCPServerStdio(tool_filter=...)` | Result (measured with the bundled scenario) |
|---|---|---|
| baseline | `allowed_tool_names=["read_asset"]` | 1 exposed MCP tool; `read_asset -> s3:GetObject` potentially allowed via `aws:role/demo-storage-mcp` |
| candidate | removed | AI-BOM unchanged; `mcp_tool_exposure_added` **critical** for `run_maintenance` (inventory capability `command_execution`), `low` for `purge_asset`; `privilege_path_added` **high** for `purge_asset -> s3:DeleteObject` under the server's role |
| fixed | restored | `potential_privilege_removed`; baseline vs fixed: 0 changes, 0 unknowns |

The server is also listed in `.mcp.json`; that entry is recorded as a
*configured* client and never creates capability paths.

## What is supported

| Layer | Supported in P0 | Everything else |
|---|---|---|
| Agent definition | Python OpenAI Agents SDK `x = Agent(...)` / `Agent[T](...)` (module or function scope) in production sources | Unknown / not reported |
| Tool binding | Explicit `tools=[...]` resolved by the existing binding analysis (same tool component IDs as the inventory, incl. imported tools and `TOOLS` lists) | `tool_definition_unresolved` |
| Tool → operation | `boto3.client("<svc>")`, `boto3.Session().client(...)`, or a factory function / `self._method()` returning one for a single known service; method mapped by `operations.ACTIONS` (S3, DynamoDB, Secrets Manager, some IAM), otherwise derived from the API name and flagged `action-derived-from-api-name`, in the tool body **or in project helpers it calls (≤3 hops, cross-file, each hop kept as evidence)**; the client may be imported from another module; or an explicit `tools:` entry in the manifest | `boto3.resource`, dynamic dispatch: not seen. A bucket passed as a helper parameter stays `*` |
| Agent → identity | **Only** the identity manifest, matched by `<file>:<variable>` | `identity_unmapped`; never inferred from names |
| MCP (P1-A) | Python `FastMCP(...)` / `MCPServer(...)` servers; `@srv.tool` tools and call-style `srv.tool(...)(fn \| self.method)` registration (also through a `register(srv)` function or method); client passed into the agent-building function resolved one call hop back; literal `require_approval` recorded; Agents SDK `Agent(mcp_servers=[...])` with `MCPServerStdio` / `MCPServerSse` / `MCPServerStreamableHttp` (assignment, `async with … as`, or imported); stdio linked to a repository server only via literal `.py` / `-m module` args; literal `tool_filter` (`create_static_tool_filter` or dict, allowed/blocked); client configs `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `mcp_config.json` (`mcpServers` / `servers`) | Remote servers: `remote_server_tools_unknown`; non-literal filter: all tools treated as exposed + `mcp_tool_filter_unresolved`; servers outside the repo: `server_outside_analyzed_sources`. Servers are never started or enumerated |
| Delegation (P1) | `handoffs=[a, handoff(b), handoff(agent=c)]` and `tools=[x.as_tool(...)]` in inline lists (an `as_tool` result may be a variable), plus `x.handoffs.append(...)` / `.extend([...])`; target must be a resolvable `Agent(...)` assignment (same file or imported). One hop | `delegate_unresolved` unknown |
| Registry (P1) | `--agent-registry approved_agents.yaml` from the operator: `registered` / `unregistered` by `agent_ref` or `file:variable` alias (case-insensitive) | No registry → `unknown`. Never read from the scan target |
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
| `mcp_tool_exposure_added` | An MCP tool newly exposed to an analyzed agent (new connection or widened filter); severity from the tool's inventory capabilities (`command_execution` → critical), +1 for untrusted instructions | yes |
| `delegate_path_added` | A parent can now delegate to a child whose operation is potentially allowed; `review_required`, severity capped at medium | **no** |
| `unregistered_agent_added` | Agent not in the supplied registry (new, or newly unlisted) | yes |

Severity and certainty are separate axes. Severity = operation hazard
(`list` low, `read` medium, `write`/`delete`/`secrets_read` high, `admin`
critical), +1 when the agent's instructions are proven to reach untrusted input
(existing prompt-flow analysis). Comparison keys are
`agent|tool|action|resource` — line numbers and JSON formatting never cause drift.
Every supported addition carries `remediation` (`why_it_matters`, conditions,
recommended actions, `retest_command`). Fixes are suggested, never applied.

## MCP semantics (P1-A)

* Graph: `agent -CONNECTS_MCP-> mcp_server -EXPOSES_TOOL-> tool`,
  `mcp_client(config) -CONFIGURES_MCP-> mcp_server`, `mcp_server -RUNS_AS-> identity`.
* A tool's *existence* on a server (`mcp_servers[].tools`) is kept separate
  from its *exposure* to an agent (`agents[].mcp_tool_ids`,
  `mcp_connections[].exposed_tool_ids`).
* An MCP tool's cloud operations are evaluated against the **server's**
  identity from the manifest (`mcp_servers: [{source, identity_ref}]`), never
  the agent's; without a mapping the verdict is `unknown`
  (`mcp_server_identity_unmapped`). Paths carry `via: "mcp"`,
  `mcp_server_id`, and the constraints `mcp-server-identity`, `tool-list-static`.
* `require_approval` on the client (`"always"`, `"never"`, or
  `{"always": {"tool_names": [...]}}`) is recorded as
  `mcp_connections[].approval`. Matching paths get the constraint
  `human-approval-required`. The verdict is unchanged, because the approval
  callback and the reviewer are runtime facts. A non-literal value is
  recorded as `unresolved`.
* Only the command's base name and the resolved repository file are stored;
  other arguments, URLs and `env` values are never written to reports.

## Delegation semantics (P1)

A delegation edge (`DELEGATES_TO`) is recorded with `guard_status: unknown`.
For each capability path of the child, a `delegate_paths` entry is emitted with
the child's verdict and the parent's verdict fixed at `unknown`
(`delegation_guard_unverified`, `identity_context_propagation_unknown`). The
child's capabilities are **never added to the parent's own capability paths**:
whether a handoff happens, which guard or approval applies, and which identity
the child runs under at that moment are runtime facts.

## Approved-agent registry (P1)

```yaml
# approved_agents.yaml — supplied by you, never auto-discovered in the target
schema_version: 1
agents:
  - agent_ref: "agent:reviewer"
    aliases: ["app/agent.py:reviewer"]
    owner: "platform-security"
```

## SARIF (P1)

`--agent-sarif` writes additions and reviews (never removals) with rule IDs
`AIBOM-AGENT-001` (`permission_scope_expanded`) … `AIBOM-AGENT-008`
(`mcp_tool_exposure_added`), a `security-severity`, the stable change ID as
`partialFingerprints.aibomChangeId`, and the operation's source line (else the
policy file) relative to the candidate root. The existing findings SARIF is
unchanged.

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
mcp_servers:                              # optional: identity of an MCP server process
  - source: "servers/storage_server.py"
    identity_ref: "aws:role/demo-storage-mcp"
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
* Implemented from P1: MCP capability graph (Python), helper/cross-file
  operations, one-hop delegation, approved-agent registry, SARIF. **Not
  implemented:** JS/TS agents and MCP servers, Graph UI; Azure/GCP/OAuth and
  runtime observation (P2).
* Evaluation: the two bundled scenarios, unit/CLI tests
  (`tests/test_agent_security*.py`), and static-extraction precision/recall on
  pinned public repositories (`benchmark/agent_security/`). Only the frozen
  held-out first run is an independent number: agents 49/49, delegations 3/3,
  MCP server tools 0/5 and operations 0/8 (the awslabs call-style
  registration, fixed afterwards). The ground truth was written by the tool
  author. Verdicts are not measured on external repositories. See
  `docs/benchmark-methodology.md`.

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
