# Detection benchmark

The benchmark compares static scan results with manually reviewed ground truth
and reports category-level Precision, Recall, F1, false positives, and false
negatives. It does not clone repositories or execute scanned code.

Run from an installed/editable checkout:

```bash
python benchmark/evaluate.py
```

Results are written to `benchmark/reports/latest.json` and `latest.md`.

For a public repository case:

1. Check out an immutable commit under a local path.
2. Add a ground-truth JSON that validates against
   `schemas/ground-truth.schema.json`.
3. Set `local_path` relative to the project root and record the full commit SHA.
4. Review every reported false positive and false negative before publishing a score.

The checked-in fixture proves the harness itself is deterministic. It is not
presented as evidence of external-repository accuracy; the candidate catalog in
`repos.yaml` must be curated and pinned before it counts toward that claim.

Two pinned public cases have been manually reviewed: OpenAI's Python quickstart
as a positive case and Flask as a negative case. Prepare their checkouts at the
`local_path` values in `ground_truth_public/*.json`, then run:

```bash
python benchmark/evaluate.py \
  --ground-truth-dir benchmark/ground_truth_public \
  --json benchmark/reports/external-latest.json \
  --markdown benchmark/reports/external-latest.md
```

The public cases are not part of the default command because the evaluator is
offline-first and does not clone repositories implicitly.

The checked-in `reports/external-latest.md` is the result for the two pinned
public cases. It currently has no mismatches, including the three Assistants
instruction prompts missed by the previous detector. The small repository set
is regression evidence and must not be presented as broad external accuracy.
