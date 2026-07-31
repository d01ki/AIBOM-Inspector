# Known limitations

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
- JS/TS precision has not been measured separately from Python. The external
  benchmark does not yet include TypeScript repositories, so TS results are
  covered by unit fixtures only.
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
- The external benchmark currently covers only two pinned public repositories
  (one positive and one negative). Its results are useful regression evidence,
  not evidence of broad ecosystem coverage; the documented threshold is 20.
- The scanner identifies references and risky configuration; it does not load,
  sandbox, or behaviorally test models.
