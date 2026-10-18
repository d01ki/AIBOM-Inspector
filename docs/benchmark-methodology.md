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

The checked-in external report (2026-10-18) covers seven manually reviewed,
commit-pinned repositories — two positive (Python, TypeScript) and five
negative (Python, JavaScript, Go). It records precision 1.0000, recall 1.0000
and F1 1.0000 with 39 true positives, no false positives and no false
negatives. The previous TypeScript misses (gateway-routed and catalog-declared
model ids in `vercel/ai-chatbot`) were fixed against those same expectations,
so the corpus is now regression evidence for that fix rather than an
independent measurement.

## Inventory accuracy vs path accuracy

The corpus scores *component inventory* (models, services, prompts, packages).
It says nothing about exposure or impact *path* accuracy. Path behavior is
pinned separately by positive, negative and unknown fixtures:
`tests/test_cross_file_python.py`, `tests/test_cross_file_typescript.py` and
`tests/test_drift_identical_bom.py`. The two must never be reported as one
number.

Do not claim broad external-repository support until at least 20 pinned public
repositories, including negative cases, are present and reviewed.
