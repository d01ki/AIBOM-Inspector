# Architecture

AIBOM Inspector is an offline-first static analysis pipeline. Scanned code is
read and parsed, but never imported or executed.

```text
CLI / HTTP API
  -> run_scan
     -> RepoCollector
        -> Python AST detector registry
        -> legacy regex compatibility detector
        -> generic model-file detector
     -> DependencyCollector
     -> Inventory normalization and deduplication
     -> optional metadata/vulnerability resolvers
     -> exposure + agent capability impact paths
     -> deterministic risk rules and score
  -> JSON / CycloneDX / SARIF / graph / self-contained HTML

Baseline scan + candidate scan
  -> prompt-slot matching (file + role + sink + ordinal; line-insensitive)
  -> exposure-path comparison
  -> agent capability impact-path comparison
  -> component / usage / finding comparison
  -> drift JSON + severity-gated CLI
```

## Detector boundary

`Detector` implementations receive an immutable `ScanContext` and emit
`Detection` objects. Each detection contains a normal inventory entity with:

- a stable detector ID;
- `file:line[:column]` evidence;
- declared/imported/instantiated/invoked state;
- `true`/`false`/`unknown` reachability;
- confidence factors;
- a value-resolution path;
- production/test/example/docs source context.

The registry supports per-detector disabling. `RepoCollector` parses each
Python file once and shares the resulting AST index between provider detectors.

## Exposure paths and behavioral drift

`build_exposure_paths` derives a path only when a prompt is proven
`user_controlled=True`. A path records the source kind, trust boundary, provider
sink, prompt role, consuming model, reachability, sanitized resolution steps,
confidence, and file/line evidence. Prompt content is never copied.

`aibom diff` compares two independently scanned inventories. Prompt entities use
a line-insensitive slot identity—source file, role, sink, and same-kind ordinal—
so unrelated line movement does not become remove/add noise. A newly proven
untrusted path into a system/developer prompt is a high-severity
`exposure_added` change even when the two revisions have identical component
sets.

`build_impact_paths` is stricter than a graph reachability join. It requires a
confirmed privileged exposure plus a direct agent tool binding and a bounded
flow from a tool parameter into a recognized high-impact operation. The
derived `ImpactPath` records the model, tool, controlled parameter, operation,
severity, reachability, confidence, and source/sink/capability evidence.

## Compatibility migration

The legacy regex detector remains enabled. For syntactically valid Python,
provider/model invocation detection is owned by AST detectors while sanitized
source (comments and docstrings removed) still feeds legacy prompt, agent, MCP,
and risk-signal rules. If AST parsing fails, the complete legacy path runs and
the failure is recorded in `stats.parse_errors`.

Inventory identity remains `<entity type, normalized name>`, so existing entity
IDs and CycloneDX `bom-ref` values are stable. New analysis data is additive in
inventory JSON and is exported as `aibom:*` CycloneDX properties.

## Analysis policy view

The normalized inventory is complete across production, test, example, and
documentation contexts. Before risk evaluation, OSV mapping, graph projection,
or behavioral path synthesis, `production_view` removes entities and signals
that have only non-production evidence. It does not mutate or delete them from
the exported inventory. This prevents deliberately vulnerable golden fixtures
and detector source strings from becoming findings against the scanner that
contains them.

## Current detector modules

- `python.openai.ast`: OpenAI SDK, async/Azure clients, LangChain OpenAI.
- `python.anthropic.ast`: Anthropic SDK/Bedrock clients, LangChain Anthropic.
- `python.huggingface.ast`: Transformers, Diffusers, Datasets,
  SentenceTransformers, Hugging Face Hub, LangChain Hugging Face.
- `python.prompt-flow.ast`: OpenAI/Anthropic/OpenAI Agents SDK prompt sinks,
  sanitized source-to-sink paths, explicit agent tool bindings, and bounded
  tool-parameter-to-operation paths.
- `legacy.regex`: compatibility and non-Python textual patterns.
- `manifest.dependencies`: Python/npm dependency declarations.
- `generic.weight-file`: serialized local model files.

## Backward-compatibility risks

- JSON consumers using strict `additionalProperties: false` must allow the new
  analysis fields.
- Valid Python files no longer report model names found only in comments,
  docstrings, or unused string assignments. This is an intentional precision
  correction.
- Entities with the same type and name are still merged across files; every
  evidence location and source context is retained.
- Reachability is same-file only in this release. `unknown` is used when there
  is no supported entrypoint or static dispatch cannot be established.

## Next migration slices

1. Extract remaining agent and MCP rules from the compatibility detector into
   independently tested detectors.
2. Add cross-file symbol/configuration resolution for YAML, JSON, and TOML.
3. Expand the call graph across imports before treating reachability as a CI gate.
4. Add MCP capability nodes and cross-file prompt paths to the graph.
