# Known limitations

- Reachability is same-file. Imported calls, dependency injection, dynamic
  dispatch, reflection, monkey patching, and framework-generated routes can
  produce `unknown` or conservative `false` results.
- Python wrapper tracing is one hop and handles straightforward positional or
  keyword forwarding only.
- Values loaded through arbitrary config-loader functions are unresolved;
  cross-file YAML/JSON/TOML linking is not implemented yet.
- JavaScript/TypeScript still uses legacy textual detectors; a syntax-aware
  parser is planned.
- Prompt source-to-sink and MCP capability analysis are not implemented in this
  slice. Existing prompt/MCP inventory remains compatibility-detector output.
- Runtime observations are not imported, so `runtime_observed` is always false.
- The external benchmark currently covers only two pinned public repositories
  (one positive and one negative). Its results are useful regression evidence,
  not evidence of broad ecosystem coverage; the documented threshold is 20.
- Assistant `instructions=` prompt arguments are not yet tracked, which causes
  three known false negatives in the current external report.
- The scanner identifies references and risky configuration; it does not load,
  sandbox, or behaviorally test models.
