# Detection benchmark

The benchmark compares static scan results with manually reviewed ground truth
and reports category-level Precision, Recall, F1, false positives, and false
negatives. It does not clone repositories or execute scanned code.

Scores are also broken down **per language** (`## By language` in the report).
Python and TypeScript are reported separately on purpose: a single blended
number would let strong Python results hide weak TypeScript ones. Set
`"language"` in each ground-truth document (`python`, `typescript`, or
`mixed`); it defaults to `python` for documents written before the split.

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

The checked-in fixtures — one Python app and one TypeScript agent — prove the
harness itself is deterministic and keep both front ends under regression
pressure. They are **not** evidence of external-repository accuracy; the
candidate catalog in `repos.yaml` must be curated and pinned before it counts
toward that claim. In particular, the pinned *public* corpus still contains no
TypeScript repository.

Ground truth records what an AIBOM *ought* to contain, not a transcript of
current scanner output. Where the two disagree, the mismatch is the finding:
the `@ai-sdk/*` provider packages were added to the service map because this
benchmark reported the missing OpenAI service as a false negative.

Six pinned public cases have been manually reviewed:

| Repository | Role | Language front end |
|---|---|---|
| `openai/openai-quickstart-python` | positive | Python |
| `vercel/ai-chatbot` | positive | TypeScript |
| `pallets/flask` | negative | Python |
| `expressjs/express` | negative | JavaScript |
| `psf/requests` | negative | Python |
| `encode/httpx` | negative | Python |

Prepare their checkouts at the `local_path` values in
`ground_truth_public/*.json` (clone, then check out the pinned commit), and run:

```bash
python benchmark/evaluate.py \
  --ground-truth-dir benchmark/ground_truth_public \
  --json benchmark/reports/external-latest.json \
  --markdown benchmark/reports/external-latest.md
```

The public cases are not part of the default command because the evaluator is
offline-first and does not clone repositories implicitly.

The checked-in `reports/external-latest.md` is the result for the pinned public
cases: precision 1.00 with no false positives anywhere, and recall 0.85 overall
(Python 1.00, TypeScript 0.79). The six recall misses are all in
`vercel/ai-chatbot` and are listed in the report rather than removed from the
ground truth — five model ids declared in a `ChatModel[]` literal and reached
via `gateway.languageModel(id)`, plus the AI Gateway service itself.

Six repositories is regression evidence and must not be presented as broad
external accuracy. The documented target is 20.
