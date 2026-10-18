# Runtime evidence (design, not implemented)

Status: design only (P2). `runtime_observed` is always `false` today.

## Goal

Let observed traces *corroborate* a static path, never replace it. A static
`potential` path whose hops are all observed at runtime can be shown as
"observed"; a static path with no observation stays exactly as it was —
**absence of a trace never means unreachable**.

## Input

OpenTelemetry spans exported to a file (OTLP JSON), produced by the user's own
instrumentation. The scanner reads the file; it never connects to a collector.

Only these attributes are read; everything else is dropped on load:

| Attribute | Use |
|---|---|
| `code.filepath`, `code.lineno`, `code.function` | match a span to a path node |
| `gen_ai.request.model` | match the model node |
| `gen_ai.tool.name` | match the bound-tool node |
| span/trace id, parent id, start time | ordering and grouping |

Never read: prompt or completion text, tool arguments, message contents,
user identifiers, HTTP bodies or headers. The loader rejects attributes
outside the allowlist rather than redacting them.

## Interface

```python
class RuntimeEvidence(Protocol):
    def observations(self) -> Iterable[Observation]: ...

@dataclass(frozen=True)
class Observation:
    file: str          # repo-relative
    line: int | None
    function: str | None
    model: str | None
    tool: str | None
    trace_id: str
    timestamp: str     # ISO 8601
```

`run_scan(..., runtime=RuntimeEvidence)` would:

1. set `UsageState.runtime_observed = True` on entities with a matching
   observation;
2. annotate each `PathNode` with `observed: bool` and keep `status`
   (`proven_static` / `potential` / `unknown`) unchanged;
3. add `runtime_corroborated: bool` to `ImpactPath` when the source, prompt,
   tool and operation nodes are observed within one trace, in order.

## Rules

- Runtime corroboration never raises severity and never upgrades `unknown` to
  `proven_static`; it is a separate column.
- No observation → no change. It is not evidence of safety.
- Observations from test or staging environments are labelled with their
  `deployment.environment` attribute and shown, not merged.
- Output keeps the same privacy contract as static evidence: identifiers,
  locations and times only.

## Why not now

The static claims had to be made sound first (evidence levels, identical-BOM
scope). Corroboration also needs a fixture trace corpus produced by real
instrumentation; synthesizing traces would test the loader, not the claim.
