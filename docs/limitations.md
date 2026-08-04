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

- Reachability is same-file. Imported calls, dependency injection, dynamic
  dispatch, reflection, monkey patching, and framework-generated routes can
  produce `unknown` or conservative `false` results.
- Python wrapper tracing is one hop and handles straightforward positional or
  keyword forwarding only.
- Values loaded through arbitrary config-loader functions are unresolved;
  cross-file YAML/JSON/TOML linking is not implemented yet.
- JavaScript/TypeScript uses a **bounded subset parser**, not a spec-compliant
  one. It models bindings, calls, members, objects, template literals, and
  function bodies, and skips type-level syntax. Constructs it does not model
  degrade to `Unknown` rather than raising, so a file can be partially analyzed
  without any signal that a specific expression was skipped. JSX children,
  `with` blocks, and label/`switch` control flow are not represented.
- JS/TS flow tracing is same-file, like the Python analysis. A tool, prompt
  constant, or sanitizer defined in another module is not followed, and
  re-exports are not resolved.
- JS/TS prompt sinks and dangerous operations come from a fixed list (Vercel AI
  SDK, OpenAI Agents, OpenAI/Anthropic Node SDKs; `child_process`, `fs`,
  `eval`/`vm`, state-changing `fetch`/`axios`, mailer sends). LangChain.js
  chains, custom provider wrappers, and framework middleware are not modeled.
- JS/TS results are measured separately from Python (`## By language` in the
  benchmark report) over one local fixture and two pinned public repositories.
  Reported precision is 1.00 with no false positives, including on a 163-file
  pure-JavaScript codebase; recall is the weaker number (see below).
- Prompt source-to-sink analysis is same-file and bounded. Cross-module helper
  calls, arbitrary sanitizers, dynamic message construction, and framework
  objects outside the recognized source/sink set remain `unknown`.
- Drift prompt matching is line-insensitive but uses the ordinal of prompts
  with the same file/role/sink. Reordering several identical sink calls can
  appear as content/target drift until structural call-site fingerprints are
  implemented.
- Trust-Boundary Drift proves static paths, not runtime exploitability. A
  framework guard or sanitizer outside the supported tracer can remain
  invisible, and `unknown` is never treated as safe.
- Agent capability impact analysis recognizes explicit bindings only — OpenAI
  Agents SDK `tools=[...]` in Python, and `tools: {…}` / `tools: [...]` in
  TypeScript — over a small high-confidence operation set per language. Dynamic
  tool registries, wrapper decorators, cross-file tools, policy middleware,
  runtime approvals, and provider-side guardrails are not modeled.
- An impact path proves that model-controlled tool parameters can reach an
  operation; it does not prove that a model will select the tool, that an
  attacker can produce the required arguments, or that runtime exploitation
  succeeds. The UI and finding text label the consequence as potential.
- MCP capability analysis is not implemented; MCP inventory remains
  compatibility-detector output.
- Runtime observations are not imported, so `runtime_observed` is always false.
- The external benchmark covers six pinned public repositories (two positive,
  four negative) plus two local fixtures. That is useful regression evidence,
  **not** evidence of broad ecosystem coverage; the documented threshold is 20.
  Large frameworks are excluded on purpose: a case only counts once every
  component has been hand-reviewed, which is not possible on a 10k-file tree.
- Public-corpus recall is currently 0.79 for TypeScript against 1.00 for
  Python. The gap is model discovery: model ids declared in a data structure
  and resolved through an indirection (`gateway.languageModel(id)`) are not
  followed, so `vercel/ai-chatbot` reports five model false negatives.
- The scanner identifies references and risky configuration; it does not load,
  sandbox, or behaviorally test models.
