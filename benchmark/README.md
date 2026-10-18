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

Seven pinned public cases have been manually reviewed:

| Repository | Role | Language front end |
|---|---|---|
| `openai/openai-quickstart-python` | positive | Python |
| `vercel/ai-chatbot` | positive | TypeScript |
| `pallets/flask` | negative | Python |
| `expressjs/express` | negative | JavaScript |
| `psf/requests` | negative | Python |
| `encode/httpx` | negative | Python |
| `gin-gonic/gin` | negative | Go (pattern tier) |

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
cases as of 2026-10-18: precision 1.00, recall 1.00 (39 TP, 0 FP, 0 FN).

Until 2026-10-18 recall was 0.85 overall (TypeScript 0.79): five model ids
declared in a `ChatModel[]` literal and reached via `gateway.languageModel(id)`,
plus the AI Gateway service, were missed in `vercel/ai-chatbot`. Those six
expectations were **not** edited; the scanner now finds them
(`javascript.model-catalog.ast`). Because they are exactly what the fix was
written against, this corpus now measures regression, not generalization.
`tests/test_js_model_catalog.py::test_ai_chatbot_external_regression` re-runs
the case whenever the checkout is present.

Seven repositories is regression evidence and must not be presented as broad
external accuracy. The documented target is 20; expanding it with
*previously unseen* positive repositories is the open item.

To prepare every checkout at its pinned SHA without executing anything:

```bash
for gt in benchmark/ground_truth_public/*.json; do
  python - "$gt" <<'PY'
import json, subprocess, sys
d = json.load(open(sys.argv[1]))
path, sha = d["local_path"], d["commit"]
subprocess.run(["git", "init", "-q", path], check=True)
subprocess.run(["git", "-C", path, "remote", "add", "origin",
                f"https://github.com/{d['repository']}.git"], check=False)
subprocess.run(["git", "-C", path, "fetch", "-q", "--depth", "1", "origin", sha], check=True)
subprocess.run(["git", "-C", path, "checkout", "-q", "FETCH_HEAD"], check=True)
PY
done
```
