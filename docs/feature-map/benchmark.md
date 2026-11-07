# Benchmark

## Overview

Ground-truth labeled repositories (`benchmark/ground_truth*`) score detection
precision and recall, agent-security verdicts, and comparisons with other
tools. Published numbers in `benchmark/reports/` come from these evaluators.
See [benchmark-methodology.md](../benchmark-methodology.md).

## Entry points

`python -m benchmark.evaluate`, `python -m benchmark.agent_security.evaluate`,
and `python -m benchmark.competitors.compare` (they need `benchmark/checkouts/`,
cloned per `benchmark/repos.yaml`).

## Source

`benchmark/**`.

## Depends on

The scan pipeline and agent security. External checkouts (network) for full
runs.

## Normal paths

The evaluators load ground truth, scan the checkouts, and write
`benchmark/reports/*.json|md`.

## Error paths

A missing checkout is skipped and reported. Ground truth must validate against
`benchmark/schemas/ground-truth.schema.json`.

## Boundaries

The held-out set (`*_heldout`) must never be used to tune detectors.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_benchmark.py tests/test_competitor_compare.py` | the evaluator logic and schema on bundled fixtures |
| a full benchmark run over `benchmark/checkouts` | the published numbers are reproducible. **Manual**: slow, and needs the clones |

## Expected results

The unit tests pass. A full run is NOT RUN unless a human ran it. Changing a
published report needs a human review.

## Evidence

pytest output. For a full run, the regenerated report diff.

## Known gaps / what usually breaks

Detector changes (including new relationships) can move the published numbers.
Rerun the benchmark before quoting them.

```json verify
{
  "id": "benchmark",
  "paths": [
    "benchmark/**"
  ],
  "tests": [
    "tests/test_benchmark.py",
    "tests/test_competitor_compare.py"
  ],
  "smoke": [],
  "ui": [],
  "manual": [
    "Full benchmark run over benchmark/checkouts and review of the report diff (slow; needs the cloned repositories)."
  ]
}
```
