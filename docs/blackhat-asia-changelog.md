# Black Hat Asia 2027 changelog

Changes relative to the previous (Europe) state, `main` at `e4ce96a`.
Measured 2026-10-18 on Windows 11, Python 3.10.11. Numbers below were
produced by the commands listed with them; nothing is estimated.

## What changed

| Area | Before | After |
|---|---|---|
| Flow scope | same file only | cross-file, bounded: imports, re-exports, tsconfig `paths`; parameters to call sites, calls through returns, imported constants |
| Tool binding | tool defined in the same file | tool imported from another module (also `TOOLS` lists, barrels, one-level TS factory); operation may be in a helper (≤3 levels) |
| Reachability | same-file entrypoint | cross-file callers up to an entrypoint, path recorded as `file:function` hops |
| Path grading | one level | `proven_static` / `potential` / `unknown`, independent of severity; potential capped at High |
| Drift identity | prompt slot (file/role/sink/ordinal) | slot, then semantic key ignoring files, lines and names |
| BOM verdict | `components_identical` boolean in the API only | `bom` with compared types, added/removed/changed; `security_boundary_changed` |
| Drift kinds | added/removed | + `impact_path_changed`, `impact_path_unresolved` (never gates) |
| JS/TS models | provider factory literals only | AI Gateway calls (invoked) and model catalogs (declared) |
| Python models | Agents SDK `Agent(model=...)` not inventoried | inventoried with the OpenAI service |
| Web UI | single-revision scan | + Compare revisions panel with clickable path graph |
| Demo | same-file impact + drift | + five-step cross-file demo (CLI, API, UI) |
| Web safety | URL/host/ref allowlists, timeout | + checkout size/file caps, no symlink checkout, no following symlinks out of the root |
| Exports | — | evidence level in findings, SARIF result properties, CycloneDX `aibom:prompt_flow_evidence_level` / `_cross_file` |

Commits: `7f84d06` (P0-A), `c079411` (P0-B Python), `0a16127` (P0-B TS),
`0de2f85` + `a54e225` (P0-C), `5407aae` + `05af2c3` (P0-D).

## Measured results

### Tests and static checks

```bash
uv run ruff check .   # All checks passed!
uv run mypy           # Success: no issues found in 61 source files
uv run pytest         # 396 passed, 1 skipped
```

Before: 340 passed. The skipped test checks that the scanner does not follow
symlinks out of the scan root; it needs symlink privileges, which this Windows
machine lacks, and runs on Linux CI.

New suites: `test_js_model_catalog.py` (8), `test_cross_file_python.py` (14),
`test_cross_file_typescript.py` (11), `test_drift_identical_bom.py` (13),
plus additions to the server, clone, CLI, web-UI, CycloneDX-schema and
detector suites.

### Component inventory — pinned public corpus

```bash
python benchmark/evaluate.py --ground-truth-dir benchmark/ground_truth_public \
  --json benchmark/reports/external-latest.json \
  --markdown benchmark/reports/external-latest.md
```

| | Before | After |
|---|---:|---:|
| Repositories | 7 | 7 |
| Overall P / R / F1 | 1.0000 / 0.8462 / 0.9167 | 1.0000 / 1.0000 / 1.0000 |
| Models recall | 0.2857 | 1.0000 |
| Services recall | 0.5000 | 1.0000 |
| TypeScript recall | 0.7857 | 1.0000 |
| TP / FP / FN | 33 / 0 / 6 | 39 / 0 / 0 |

The baseline numbers were re-measured on `e4ce96a` and matched the checked-in
report byte for byte. **Caveat:** the six fixed false negatives are the
expectations the fix targeted, so the "after" column is regression evidence,
not an independent accuracy claim. The local fixture benchmark
(`python benchmark/evaluate.py`) is unchanged: 51 TP, 0 FP, 0 FN.

### Path behavior — fixtures

Path accuracy is not measured on a public corpus. It is pinned by fixtures:

| Case | Expected | Python | TS |
|---|---|---|---|
| 4-file positive | proven Critical, every file in evidence | ✓ | ✓ |
| identical-BOM baseline (sanitizing helper) | no path | ✓ | ✓ |
| user role only | no privileged path | ✓ | ✓ |
| tool not bound | exposure, no impact | ✓ | ✓ |
| fixed command | no capability | ✓ | ✓ |
| unresolved helper / external package | `potential`, capped at High | ✓ | ✓ |
| reflective / dynamic import | not proven; `unknown`, never gates | ✓ | ✓ |
| missing tsconfig alias | `unknown` reachability, not safe | — | ✓ |
| cyclic imports, recursion | terminates with `cycle` | ✓ | ✓ |
| ambiguous / same-name modules | exact match only, no guessing | ✓ | ✓ |
| 40-module helper chain | bounded, never "safe" | ✓ | — |
| line shift + rename + file move | no drift | ✓ | — |

### Performance

Wall time of `run_scan(path, lockfiles=False)` on the pinned checkouts, one
run each, same machine:

| Repository | Files | Before (s) | After (s) |
|---|---:|---:|---:|
| pallets/flask | 195 | 3.27 | 3.23 |
| encode/httpx | 98 | 3.36 | 3.45 |
| psf/requests | 82 | 2.17 | 2.25 |
| expressjs/express | 163 | 5.34 | 5.72 |
| vercel/ai-chatbot | 165 | 5.22 | 5.64 |

Overhead of the project index and cross-file tracing: within ~8%.

## Not done (explicitly)

- **P1 — MCP / agent capability graph.** Not implemented. MCP tool handlers
  remain untrusted *entrypoints*; MCP tool operations are not joined into
  `declared → registered → bound → potentially reachable` states. The project
  index and `_capabilities_in` helper descent are the intended building
  blocks: a `@mcp.tool` / `server.tool(...)` handler can reuse the same
  parameter-to-operation proof, with `registered` as its binding state.
- **P1 — corpus of 20+ repositories and competitor comparison.** Not done.
  The corpus is still seven repositories, and the competitive table in
  [novelty-positioning](novelty-positioning.md) is a documentation review,
  not an experiment; no competitor tool was run.
- **P2 — runtime evidence.** Design only: [runtime-evidence-design](runtime-evidence-design.md).
- Docker image build was not re-run in this environment (Docker daemon
  unavailable). The equivalent install path was verified: the wheel built
  with `uv build`, installed into a clean venv, runs the full five-step
  `aibom demo` offline; the Dockerfile copies the four new fixtures the wheel
  needs.

## Residual risks

- The bounded TS parser may silently skip an unmodeled construct inside a
  path; the result is a missed path (`unknown`), not a false Critical.
- Semantic matching treats two different paths with the same source kind,
  sink kind, boundary and capability signature as the same path.
- A sanitizer that returns a transformed version of its input is not trusted;
  that can over-report on code that does sanitize.
- A potential path is still a High finding; reviewers should read its
  `limitations` before acting on it.
