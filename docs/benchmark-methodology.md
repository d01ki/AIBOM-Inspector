# Benchmark methodology

`benchmark/evaluate.py` compares offline scans with manually curated ground
truth and produces JSON and Markdown reports.

## Matching

A component match requires the same normalized category and name. If ground
truth specifies a file and line, at least one evidence location must match it.
Each prediction and expected component can match at most once. Unmatched
predictions are false positives; unmatched expected components are false
negatives.

The report provides micro-averaged overall and category metrics. Categories
with no expected components and no predictions show `N/A`, not a perfect score.

## Scan mode

The harness scans with lockfile resolution **off**. Ground truth records the
components a repository declares; lockfile resolution correctly adds transitive
components that no hand-authored ground truth lists, and scoring those as false
positives would make precision meaningless. Lockfile coverage is exercised by
the unit tests (`tests/test_lockfiles.py`), not by this corpus.

## Reproducibility rules

- Public repositories must be pinned to immutable full commit SHAs.
- Ground truth must validate against the checked-in JSON Schema.
- Reviews must include negative repositories and production/test/example code.
- The evaluator never clones or executes repositories; checkout preparation is
  an explicit, auditable step.
- A checked-in synthetic fixture validates the harness but is not evidence of
  external-repository accuracy.

The external corpus (2026-10-18) has 20 manually reviewed, commit-pinned
repositories: 9 positive and 11 negative. Ground truth for the 13 newest
cases was written before the scanner ran on them, and that first run is
frozen:

| Run | Repos | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| First run on 13 unseen cases + 7 earlier (frozen: `reports/external-20-unseen.md`) | 20 | 0.913 | 0.661 | 0.767 | 84 | 8 | 43 |
| After fixing what that run exposed (`reports/external-latest.md`) | 20 | 0.966 | 0.869 | 0.915 | 113 | 4 | 17 |

Corrections to ground truth after the first run are limited to curation
mistakes against rules written down beforehand, and each is recorded in the
case's `notes` (see `benchmark/README.md`, *Protocol*).

## Inventory accuracy vs path accuracy

The corpus scores *component inventory* (models, services, prompts, packages).
It says nothing about exposure or impact *path* accuracy. Path behavior is
pinned separately by positive, negative and unknown fixtures:
`tests/test_cross_file_python.py`, `tests/test_cross_file_typescript.py` and
`tests/test_drift_identical_bom.py`. The two must never be reported as one
number.

Do not claim broad external-repository support until at least 20 pinned public
repositories, including negative cases, are present and reviewed.
