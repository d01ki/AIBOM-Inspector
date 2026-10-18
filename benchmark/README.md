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

Twenty pinned public cases have been manually reviewed. The first seven
predate 2026-10-18; the other thirteen were curated that day by reading every
source file **before** running the scanner on them (see *Protocol* below):

| Repository | Role | Language front end |
|---|---|---|
| `openai/openai-quickstart-python` | positive | Python |
| `vercel/ai-chatbot` | positive | TypeScript |
| `pallets/flask` | negative | Python |
| `expressjs/express` | negative | JavaScript |
| `psf/requests` | negative | Python |
| `encode/httpx` | negative | Python |
| `gin-gonic/gin` | negative | Go (pattern tier) |
| `modelcontextprotocol/quickstart-resources` | positive | mixed (Python, TS, Go, Ruby, Rust) |
| `openai/openai-assistants-quickstart` | positive | TypeScript |
| `vercel-labs/ai-sdk-preview-roundtrips` | positive | TypeScript |
| `vercel-labs/gemini-chatbot` | positive | TypeScript |
| `openai/openai-realtime-agents` | positive | TypeScript |
| `openai/openai-structured-outputs-samples` | positive | TypeScript |
| `simonw/llm-claude-3` | positive | Python |
| `pallets/click` | negative | Python |
| `fastapi/typer` | negative | Python |
| `pallets/markupsafe` | negative | Python |
| `pallets/jinja` | negative | Python |
| `sindresorhus/ky` | negative | TypeScript |
| `expressjs/cors` | negative | JavaScript |

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

## Results (2026-10-18)

| Run | Repos | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| First run on 13 unseen cases + 7 earlier (frozen: `reports/external-20-unseen.md`) | 20 | 0.913 | 0.661 | 0.767 | 84 | 8 | 43 |
| After fixing what that run exposed (`reports/external-latest.md`) | 20 | 0.966 | 0.869 | 0.915 | 113 | 4 | 17 |

Only the first row measures generalization. The errors it listed were real
scanner defects (semicolon-free JS imports, `as T[]` casts, MCP clients read
as servers, unmodeled OpenAI call shapes, manifest line attribution, ...);
each fix has a regression test in `tests/test_corpus_regressions.py` that
fails on the pre-fix code.

The seven-case corpus that preceded it scores 39 TP / 0 FP / 0 FN; its six
former TypeScript misses were the target of the gateway/catalog fix, so it is
regression evidence too.

## Protocol for new cases

1. Pin the full commit SHA; clone shallowly; never install or run anything.
2. Read every source file and manifest; write the ground truth and its
   `notes` (every judgment call) **before** scanning the checkout.
3. Run the evaluator once and freeze that report.
4. Fix scanner defects; add a regression test that fails before the fix.
5. Correct the ground truth only for curation mistakes against a rule written
   down beforehand (e.g. prompt names carry the prompt expression's line), and
   say so in the case's `notes`. Never drop an expectation to raise a score.

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
