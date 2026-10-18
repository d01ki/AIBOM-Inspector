# Black Hat Asia 2027 demo

> **An AIBOM does not change. The attack surface does.**

The demo shows one claim, reproducibly and offline: two revisions with an
identical component inventory, where the second gains a path from untrusted
input, through privileged instructions and a model, to an explicitly bound
tool that runs a command. The path crosses four files. Nothing is executed.

## Preparation

Any one of these works without network access once installed:

```bash
./aibom demo                          # launcher: builds/uses the Docker image
docker compose run --rm demo          # same, via Compose
pip install ".[server]" && aibom demo # no Docker
```

For the visual version: `./aibom ui` (or `aibom serve`), open the printed URL,
scroll to **03 Compare revisions**.

Fixtures (shipped in the wheel and the image):

| Revision | Python | TypeScript |
|---|---|---|
| baseline (also the *fixed* revision) | `tests/fixtures/xfile-py-baseline` | `tests/fixtures/xfile-ts-baseline` |
| candidate | `tests/fixtures/xfile-py-candidate` | `tests/fixtures/xfile-ts-candidate` |

The two revisions differ in one file only — the prompt builder:

```python
# baseline: prompts/builder.py
return POLICY + "\nCategory: " + _category(problem)   # _category returns literals

# candidate: prompts/builder.py
return POLICY + "\nReported problem: " + problem
```

## The five steps

| Step | CLI (`aibom demo`) | Web UI (Compare revisions) |
|---|---|---|
| 1. Baseline | `1/5 Baseline 1 model, 2 package, 1 service; 0 impact path(s)` | Baseline card |
| 2. Candidate | `2/5 Candidate 1 impact path(s)` | Candidate card |
| 3. Same BOM | `Component BOM unchanged (compared 4 components: model, package, service; ...)` | green **Component BOM — Unchanged** |
| 4. New path | `critical / proven statically / impact_path_added` and the hop list | red **Security boundary — Changed**, path graph |
| 5. Fix | `5/5 Fix ... 1 path(s) removed; security boundary unchanged.` | **Rescan the fixed revision** |

Expected path (Python):

```text
source       routes/api.py:11        http_parameter (route parameter `problem`)
flow         routes/api.py:11        call_argument -> run_support_agent(problem)
flow         assistant/main.py:12    call_argument -> build_instructions(problem)
flow         prompts/builder.py:8    return_value  (POLICY + ... + problem)
prompt       assistant/main.py:9     openai.agents.Agent.instructions (system)
model        assistant/main.py:9     gpt-4.1
tool         tools/executor.py:11    run_diagnostic, explicitly bound, param `command`
operation    tools/executor.py:16    subprocess.run (command_execution)
```

TypeScript is the same shape: `app/api/support/route.ts` → `@/lib/agent`
(tsconfig path) → `lib/prompts.ts` → `generateText({ system })` →
`tools: { runDiagnostic }` imported from `lib/tools/diagnostics.ts` →
`execSync(command)` in a helper.

CI gate, same verdict:

```bash
aibom diff tests/fixtures/xfile-ts-baseline tests/fixtures/xfile-ts-candidate --fail-on critical
echo $?   # 1
```

API, same verdict: `POST /api/diff/demo?language=python&scenario=cross-file`
(and `&revision=fixed` for step 5), or `POST /api/diff` with a repository URL
and two refs.

## What to say while it runs

- "The inventory is identical — same model, packages, service, same tool with
  the same `subprocess.run`. A component diff says nothing changed."
- "One `return` line moved user input into the builder's output. The tool was
  always powerful; it is newly *steerable*."
- "Every hop is a file and a line. Nothing was imported, installed, or run."
- "Critical here is the impact class of the operation, and the evidence is
  *proven statically*. That is a static path, not a demonstrated exploit."

## Technical explanation (one slide)

1. Parse every Python and JS/TS file once into a project index: modules,
   top-level bindings, imports, re-exports, tsconfig paths.
2. Trace the privileged prompt argument backwards, bounded: assignments,
   composition, a parameter to its resolved call sites, a call through the
   callee's returns, an imported constant to its definition.
3. Resolve the explicit `tools=[...]` / `tools: {...}` binding — across
   modules — and prove a tool parameter reaches a recognized operation.
4. Grade the path: `proven_static`, `potential` (an unresolved call or route;
   capped at High), or `unknown` (shown, never gated).
5. Diff two scans: BOM identity over a stated scope, and paths matched by a
   line/file/rename-insensitive key so refactors are not drift.

## Expected questions

**Is this taint analysis? That exists.** Yes, bounded taint analysis exists
in many tools. The distinct part is joining *role-aware* prompt lineage (system
vs user), an *explicit* agent-tool binding, a tool-parameter-controlled
operation, and AI-BOM component identity — then diffing that path across two
revisions whose BOM is identical.

**Does it prove the attack works?** No. It proves a static data path. It does
not prove the model selects the tool, that an attacker can shape the argument,
or that no runtime guard exists. Every path says so in its `limitations`.

**What about frameworks, DI, decorators?** Unresolved → `unknown`, never
"safe". A taint through an unresolved call keeps the path as `potential`,
which can never be Critical. See [limitations](limitations.md).

**What if I move or rename code?** Paths are matched by a semantic key that
ignores files, lines and function names; the relocation test moves the agent
factory, renames the builder and shifts lines with no reported drift.

**What if the user input only goes into the user message?** Not privileged,
no impact path (`test_user_role_only_flow_is_not_privileged`,
`test_user_message_only_is_not_a_privileged_change`).

**How accurate is it on real code?** Component inventory on 20 pinned public
repositories, ground truth written before scanning: the first run on the 13
unseen cases scored precision 0.913, recall 0.661, with no false positive on
any of the 11 negative repositories. After fixing what that run exposed: 0.966
/ 0.869 — but that is now a seen corpus. Quote the first number. Path accuracy
is pinned by positive/negative/unknown fixtures, not by a public corpus yet.

**Does it run MCP servers or call models?** No. It reads text.

**Is MCP capability analysis included?** A first version: MCP and agent tools
are inventoried with a reachability ladder, and a registered MCP tool whose
parameter reaches a command is `potentially_reachable` (High at most). It does
not model MCP dispatch tables, client-side approval, or server configuration;
keep it out of the main demo and mention it as scope.

## If something goes wrong on stage

- No Docker: `pip install ".[server]"` from a local checkout, then `aibom demo`.
- Narrow terminal: the CLI tables are tested at 80 columns.
- Browser: the UI needs the backend (`aibom serve`); a static copy of the page
  shows "No analysis backend" instead of failing silently.
