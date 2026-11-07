# Feature map

What this repository does, feature by feature, and how to **prove** each one
works. It is the reference the [verify skill](../.claude/skills/verify/SKILL.md)
and `scripts/verify.py` use to decide which checks a change needs. A change is
not "done" because it compiles or because an agent says so; it is done when the
checks for every feature it touches have run and left evidence.

| Feature | File | Touches |
|---|---|---|
| Scan pipeline | [scan-pipeline.md](feature-map/scan-pipeline.md) | detectors, collectors, inventory, risk rules, CLI `scan` |
| Dependency map | [dependency-map.md](feature-map/dependency-map.md) | manifests, lockfile edges, component linker, graph, Dependencies tab |
| Exports & conformance | [exports.md](feature-map/exports.md) | CycloneDX, SARIF, HTML report, `aibom conformance` |
| Behavioral drift | [drift.md](feature-map/drift.md) | `aibom diff`, `/api/diff*`, compare view, `aibom demo` |
| Agent security | [agent-security.md](feature-map/agent-security.md) | identity / IAM / MCP privilege drift, scenarios |
| Online enrichment | [enrichment.md](feature-map/enrichment.md) | Hugging Face resolver, OSV mapping (network) |
| HTTP API | [server-api.md](feature-map/server-api.md) | FastAPI app, repo cloning, CORS |
| Web UI | [web-ui.md](feature-map/web-ui.md) | `web/index.html` single-page app |
| Benchmark | [benchmark.md](feature-map/benchmark.md) | ground truth, evaluators, competitor comparison |
| Verification harness | [verification.md](feature-map/verification.md) | this map, `scripts/verify*.py`, the verify skill |
| Distribution | [distribution.md](feature-map/distribution.md) | packaging, Docker, launchers, CI/CD workflows |

## Conventions

Each feature file answers the same questions, in this order:

1. **Overview**: what exists and why.
2. **Entry points**: how a user reaches it (CLI, API, UI).
3. **Source**: the files that implement it.
4. **Depends on**: other features or components it relies on.
5. **Normal paths**, **Error paths**, **Boundaries**: what to exercise.
6. **How to verify**: the commands, and what each one proves.
7. **Expected results**.
8. **Evidence**: what to keep (exit codes, logs, JSON, screenshots).
9. **Known gaps / what usually breaks**.

Each file ends with one fenced block tagged `json verify`, which the tooling
reads:

```text
{
  "id": "feature-id",
  "paths": ["glob relative to the repo root", "..."],
  "tests": ["tests/test_x.py", "..."],
  "smoke": [
    {"name": "...", "cmd": ["{py}", "-m", "aibom.cli", "..."],
     "expect_exit": 0, "expect_files": ["{out}/x.json"], "expect_output": "text"}
  ],
  "ui": ["fixture-name"],
  "manual": ["a check that cannot be automated, reported as NOT RUN"]
}
```

`{py}` is the current Python interpreter. `{out}` is the evidence directory of
the run. `paths` globs may overlap: a file can belong to several features, and
a change runs the checks of every feature that claims it.

`tests/test_feature_map.py` enforces that every glob matches a file, every
test file exists, and every file under `src/aibom/` and `web/` belongs to at
least one feature. A new module therefore fails CI until it is placed on this
map.

## Sweep order

For a broad regression sweep (`python scripts/verify.py --all`), the features
run in the table order above. Run *Scan pipeline* first because every other
feature consumes its inventory. Run *Distribution* last because it is the
slowest and most of its checks need a human (Docker, release, Pages).

## Maintenance

Update the feature file in the same PR as the behavior change. When a bug
escapes, add the regression test to that feature's `tests` list. If the check
can be decided mechanically, move it into a test or lint rule rather than
adding prose here (see [the verify skill's failure-to-skill
loop](../.claude/skills/verify/SKILL.md#failure-to-skill)).
