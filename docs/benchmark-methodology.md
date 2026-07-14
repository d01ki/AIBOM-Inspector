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

## Reproducibility rules

- Public repositories must be pinned to immutable full commit SHAs.
- Ground truth must validate against the checked-in JSON Schema.
- Reviews must include negative repositories and production/test/example code.
- The evaluator never clones or executes repositories; checkout preparation is
  an explicit, auditable step.
- A checked-in synthetic fixture validates the harness but is not evidence of
  external-repository accuracy.

The checked-in external report currently covers two manually reviewed,
commit-pinned repositories. It records precision 1.0000, recall 0.7273, and F1
0.8421; the three false negatives are OpenAI Assistants `instructions=` prompt
arguments. These are retained in the report as an explicit detector backlog.

Do not claim broad external-repository support until at least 20 pinned public
repositories, including negative cases, are present and reviewed.
