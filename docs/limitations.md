# Known limitations

## Language coverage is two-tier

- **Python and JavaScript/TypeScript** are parsed into a syntax tree, so they
  get prompt-flow, blast-radius and drift analysis.
- **Go, Java, Kotlin, Rust, Ruby, C#, PHP, Swift and Scala** are read by the
  pattern layer only: dependencies, model ids, provider SDK imports, prompt
  constants and secrets. They **never** yield an impact path, an exposure path
  or a drift verdict, because those claims need a parse tree to be honest.
  Anything else — every other language, and any construct the regex rules do
  not name — is not analyzed at all.
- Dependency manifests are parsed for PyPI, npm, Go, crates.io, Maven,
  RubyGems, Packagist and NuGet. Lockfiles are read for **npm
  (`package-lock.json`), PyPI (`Pipfile.lock`, `poetry.lock`, `uv.lock`,
  hash-pinned `requirements*.txt`), crates.io, Packagist and RubyGems**, which
  is where transitive components and artifact digests come from. Without one of
  those lockfiles, transitive dependencies are absent — the emitted SBOM says
  so in `cisa:coverage` rather than implying completeness. `yarn.lock` and
  `pnpm-lock.yaml` need a YAML parser this project does not depend on;
  `go.sum` records module-tree hashes rather than artifact digests, so it is
  not used (`go.mod` already lists resolved versions).
- Dependencies are never resolved over the network: what is not in the
  repository is not in the BOM.
- Maven version resolution follows a single `${property}` indirection in the
  same POM. Parent POMs, `dependencyManagement`, BOM imports and Gradle version
  catalogs are not resolved, so some versions stay unknown.

- Reachability and prompt flow are **cross-file but bounded** (since 2026-10).
  A project-wide index resolves the statically resolvable subset of imports:
  Python absolute and relative imports (`import a.b`, `from ..x import y`,
  re-exports through `__init__.py`), and JS/TS relative specifiers,
  `export { a as b } from`, `export * from`, namespace imports and
  `tsconfig.json` `paths` of the `"@/*": ["./*"]` shape (root tsconfig/jsconfig
  only; no `extends`, no nested project references). Across that subset the
  tracers follow a parameter to its resolved call sites, a call through the
  callee's `return` values, and an imported constant to its definition.
- What stays unresolved, and is reported as `unknown` rather than safe:
  bare package specifiers (code in `node_modules`/site-packages is never read),
  dynamic `import()`/`importlib`/`getattr`, method calls on objects
  (`self.helper(x)`, `client.build(x)`), dependency injection, decorators that
  wrap a function, monkey patching, framework-generated routes, and a module
  name that matches more than one file (`svc_a/tools/x.py` and
  `svc_b/tools/x.py` for `import tools.x`) — ambiguity is never guessed.
- Bounds: 4 call boundaries, 8 call sites per function, 4,000 expression visits
  per trace, 6 re-export hops, 3 helper levels below a tool. A path cut by a
  bound carries an `analysis_budget_exhausted` step and cannot be proven.
- Untrusted input passing through a call the index cannot see is assumed to
  propagate (an `unresolved_call` step). That keeps the flow, but marks any
  resulting path `potential`: it is never reported as Critical. A small list
  of pure transformations (`str`, `.format`, `.join`, `.strip`, `String`,
  `.trim`, `JSON.stringify`, ...) does not weaken a proof.
- Sanitization is recognized only structurally: a helper whose `return`
  values do not depend on the tainted parameter (an allowlist returning
  literals) breaks the flow. A sanitizer that returns a transformed version of
  its input (`re.sub`, `escape`) is not trusted.
- Values loaded through arbitrary config-loader functions are unresolved;
  cross-file YAML/JSON/TOML linking is not implemented yet.
- JavaScript/TypeScript uses a **bounded subset parser**, not a spec-compliant
  one. It models bindings, calls, members, objects, template literals, and
  function bodies, and skips type-level syntax. Constructs it does not model
  degrade to `Unknown` rather than raising, so a file can be partially analyzed
  without any signal that a specific expression was skipped. JSX children,
  `with` blocks, and label/`switch` control flow are not represented.
  `export default function name()` is not indexed as the `default` export.
- JS/TS prompt sinks and dangerous operations come from a fixed list (Vercel AI
  SDK, OpenAI Agents, OpenAI/Anthropic Node SDKs; `child_process`, `fs`,
  `eval`/`vm`, state-changing `fetch`/`axios`, mailer sends). LangChain.js
  chains, custom provider wrappers, and framework middleware are not modeled.
- JS/TS model ids reached through the Vercel AI Gateway are recorded as
  *invoked* only when the `gateway.languageModel(...)` argument resolves
  statically (also through an imported object). Ids in a model catalog are
  recorded as *declared* only, and only when the codebase imports an AI SDK and
  the id has a known vendor prefix (`openai/`, `anthropic/`, `xai/`, ...). A
  runtime-selected id (a function parameter, `process.env`) is never invented.
- Drift matches paths by prompt slot (file/role/sink/ordinal), then by a
  semantic key (source kind, sink kind, trust boundary, bound capability
  signature) that ignores files, lines and function names. Two *different*
  paths with an identical semantic key, where one is removed and the other
  added in the same change, are reported as unchanged.
- "Component BOM unchanged" means: the same set of non-prompt entities (models,
  packages, services, agents, datasets) with the same names, versions and
  security metadata. Prompts are excluded from that verdict on purpose and are
  compared as exposure and impact paths.
- Trust-Boundary Drift proves static paths, not runtime exploitability. A
  framework guard or sanitizer outside the supported tracer can remain
  invisible, and `unknown` is never treated as safe.
- Agent capability impact analysis recognizes explicit bindings only — OpenAI
  Agents SDK `tools=[...]` in Python (also an imported tool or an imported
  `TOOLS` list), and `tools: {…}` / `tools: [...]` in TypeScript (also an
  imported tool, through barrels, or one level of tool factory) — over a small
  high-confidence operation set per language. Dynamic tool registries, wrapper
  decorators, policy middleware, runtime approvals, and provider-side
  guardrails are not modeled.
- An impact path proves that model-controlled tool parameters can reach an
  operation; it does not prove that a model will select the tool, that an
  attacker can produce the required arguments, or that runtime exploitation
  succeeds. The UI and finding text label the consequence as potential.
- Tool inventory and the MCP capability graph cover: Python `@function_tool`,
  LangChain `@tool`, MCP `@<server>.tool()` (in a module importing `mcp` or
  `fastmcp`); TypeScript `server.tool(...)` / `server.registerTool(...)` (in a
  module importing `@modelcontextprotocol/sdk`) and `tool({...})` from `ai` or
  `@openai/agents`, including `const make = (deps) => tool({...})` factories.
  Not covered: `server.setRequestHandler(CallToolRequestSchema, ...)` dispatch
  tables, tools registered in a loop or from a registry object, MCP server
  configuration (`mcpServers` JSON) mapped to the server code, and tool
  descriptions/schemas (a description is never used as evidence of danger).
- A registered MCP tool whose parameter reaches an operation is
  `potentially_reachable` because the MCP client chooses its arguments;
  authorization middleware, per-tool approval and client-side confirmation are
  not modeled. Such a change is reported at most as High.
- A binding is matched to a tool definition by name; with several tools of the
  same name, only a capability-location match counts, otherwise the binding is
  left unmatched.
- Tools are not scored by the benchmark: no curated ground truth lists tools
  yet, so the `Tools` row stays N/A.
- Runtime observations are not imported, so `runtime_observed` is always false.
- The external benchmark covers 20 pinned public repositories (9 positive,
  11 negative; Python, TypeScript/JavaScript, Go and one five-language MCP
  repository) plus three local fixtures. Small repositories only: a case
  counts once every component has been hand-reviewed, which is not possible on
  a 10k-file tree, so large frameworks and monorepos are not represented.
- The first run on the 13 newly curated cases is the only independent number:
  precision 0.913, recall 0.661 (frozen in `reports/external-20-unseen.md`).
  The defects it exposed were fixed, after which the same corpus scores 0.966 /
  0.869 — regression evidence, not generalization. All 11 negative
  repositories produced no false-positive *component* in either run.
- Risk findings are not component-free on those repositories: the
  hardcoded-secret rule (TDR-007, regex tier) fires on a placeholder token
  inside a JSDoc usage example in `sindresorhus/ky`
  (`source/types/options.ts:409`). Comments are scanned on purpose, since a
  real credential in a comment is still a leak, so such examples remain a
  known false-positive source (found by `benchmark/competitors/compare.py`).
- Still missed on that corpus (by design or not yet supported): model ids
  registered with a plugin framework rather than passed to an SDK call (the
  `llm` plugin in simonw/llm-claude-3), prompts passed to a sink only through
  `**kwargs`, and model ids that appear only in recorded test cassettes (found,
  but with test-file evidence instead of the source location).
- Attack-path accuracy (exposure and impact paths) is measured only on the
  checked-in positive/negative/unknown fixtures, not on public repositories.
  Component inventory accuracy and path accuracy must not be conflated.
- The scanner identifies references and risky configuration; it does not load,
  sandbox, or behaviorally test models.
