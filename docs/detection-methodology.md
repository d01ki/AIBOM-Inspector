# Detection methodology

## Evidence contract

Every reported entity is tied to source evidence. AST evidence includes the
detector ID, source kind, line/column span, a bounded snippet, and confidence.
No target code is imported, evaluated, or executed.

## Python analysis

The parser indexes imports and aliases, assignments by scope, parent nodes,
function calls, docstring spans, and known entrypoints. Provider detectors then
identify actual constructor/API calls rather than model-like strings alone.

The bounded value resolver supports:

- scalar string constants and variable references;
- dictionaries, lists, tuples, subscripts, and `dict.get`;
- static string concatenation and fully static f-strings;
- `os.getenv`/`os.environ.get` defaults;
- unresolved `os.environ[...]` references without exposing a secret value;
- one-hop wrapper-function argument tracing.

Unknown expressions remain `unresolved`; they are never converted into guessed
model names. Resolution steps are serialized so users can audit how a value was
derived.

## Usage classification

The states are intentionally independent:

```text
declared -> imported -> instantiated -> invoked -> reachable
                                      runtime_observed (independent evidence)
```

An SDK import creates an imported service, not an invoked model. An API call
with a model argument creates an invoked model. Manifest packages are declared
only. Runtime evidence is not yet ingested and therefore remains false.

## Reachability

The initial call graph is same-file and bounded. It recognizes FastAPI/Flask-
style routes, router routes, CLI command decorators, task/tool decorators,
common Lambda handler names, and `if __name__ == "__main__"` calls. Results are:

- `true`: a static path from a supported entrypoint was found;
- `false`: supported entrypoints exist in the file, but no same-file path was found;
- `unknown`: there is no supported entrypoint or analysis is insufficient.

`false` must not be interpreted as globally unreachable until cross-file and
dynamic dispatch analysis are implemented.

## Confidence

Confidence is separated into syntax, value resolution, framework identity,
reachability, and runtime confirmation. AST-confirmed calls receive high syntax
confidence; unresolved values and regex-only matches stay lower. The original
evidence confidence remains available for existing filters.

## Precision controls

For valid Python source, comments and docstrings are removed before legacy
matching and model-like unused constants are not inventory components. Test,
fixture, example, demo, and docs paths are tagged so downstream policy can
filter them without discarding their evidence.
