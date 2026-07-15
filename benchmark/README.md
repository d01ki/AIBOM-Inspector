# Benchmark harness

Measures AIBOM Inspector's detection **Precision / Recall / F1** against
hand-labeled ground truth, so accuracy is reproducible rather than asserted
(Black Hat plan §5).

```bash
python benchmark/evaluate.py                 # evaluate all labeled repos
python benchmark/evaluate.py --min-f1 0.9    # exit non-zero below threshold (CI)
python benchmark/evaluate.py --max-fp 0      # exit non-zero on any false positive
```

Latest results: [`reports/latest.md`](reports/latest.md).

## How it works

Each repo is described by a label in [`ground_truth/`](ground_truth/) (schema:
[`schemas/ground-truth.schema.json`](schemas/ground-truth.schema.json)) that
lists the AI components a correct scan should find. The evaluator runs a real
`aibom` scan, then compares detected vs. expected **per category** and reports
the exact false positives and false negatives.

Matching is component-level:

- **name-based** categories (`models`, `datasets`, `services`, `ai_packages`)
  match on the normalized component name;
- **location-based** categories (`prompts`, `agents`, `mcp`) match on the
  evidence *file* — those entities are named by `file:line`, and lines move.

Only AI-flagged packages count toward `ai_packages`; ordinary dependencies are
inventoried in the BOM but are not part of the AI-detection metric.

## The repository set

- **Local, labeled mini-repos** ([`repos/`](repos/)) ship with the tool and run
  offline in CI. They are deliberately small but exercise the hard cases:
  env-default model resolution (Python + JS), dict/const indirection, notebooks,
  MCP servers, and a **negative** (non-AI) repo that must yield zero detections.
  A perfect score here is a **regression gate**, not a real-world accuracy claim.
- **Public repos** ([`repos.yaml`](repos.yaml)) expand the evaluation to real
  codebases when run with network access. Labeling them is manual; the set is a
  starting point to grow toward the plan's 20–50 repositories.

## Adding a repo

1. Add the code under `repos/<name>/` (or pin a public repo in `repos.yaml`).
2. Write `ground_truth/<name>.json` listing its AI components.
3. Run `python benchmark/evaluate.py` and inspect the false-positive /
   false-negative lists until the label and the scanner agree (fix whichever is
   wrong).
