#!/usr/bin/env python3
"""Benchmark harness — measure detection Precision/Recall/F1 vs ground truth.

Compares ``aibom`` scan output against hand-labeled ground truth for a set of
repositories and reports per-category metrics plus the exact false positives and
false negatives, so accuracy claims are reproducible (Black Hat plan §5).

Repositories are labeled in ``ground_truth/*.json``. Each label points at a repo
via ``local_path`` (a checked-in mini-repo — offline, deterministic, CI-safe) or,
for networked runs, ``repository`` + ``commit`` (cloned on demand).

Matching is component-level:

* name-based categories (models, datasets, services, ai_packages) match on the
  normalized component name;
* location-based categories (agents, prompts, mcp) match on the evidence file,
  because those entities are named by ``file:line`` and lines shift.

Usage::

    python benchmark/evaluate.py              # evaluate all local labels
    python benchmark/evaluate.py --json out.json --md out.md
    python benchmark/evaluate.py --min-f1 0.9 # exit non-zero below threshold
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Allow running the script directly from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aibom.service import run_scan  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent
CATEGORIES = ["models", "datasets", "prompts", "agents", "services", "mcp", "ai_packages"]
_NAME_BASED = {"models", "datasets", "services", "ai_packages"}


# ── extracting (category, key) pairs ─────────────────────────────────────────


def _category_of(entity: dict) -> str | None:
    t = entity.get("type")
    mapping = {"model": "models", "dataset": "datasets", "prompt": "prompts",
               "agent": "agents"}
    if t in mapping:
        return mapping[t]
    if t == "service":
        return "mcp" if entity.get("kind") == "mcp" else "services"
    if t == "package":
        return "ai_packages" if entity.get("ai") else None
    return None


def _key_of(entity: dict, category: str) -> str:
    if category in _NAME_BASED:
        return str(entity["name"]).strip().lower()
    ev = entity.get("source_evidence") or [{}]
    return str(ev[0].get("file", "")).strip().lower()


def _detected_pairs(inventory: dict) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for entity in inventory.get("entities", []):
        cat = _category_of(entity)
        if cat is not None:
            pairs.add((cat, _key_of(entity, cat)))
    return pairs


def _truth_pairs(components: list[dict]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for comp in components:
        cat = comp["category"]
        key = comp.get("name") if cat in _NAME_BASED else comp.get("file")
        if key is not None:
            pairs.add((cat, str(key).strip().lower()))
    return pairs


# ── metrics ──────────────────────────────────────────────────────────────────


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, other: Counts) -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class RepoResult:
    name: str
    false_positives: list[tuple[str, str]] = field(default_factory=list)
    false_negatives: list[tuple[str, str]] = field(default_factory=list)


def evaluate_all(*, clone: bool = False) -> dict:
    per_category: dict[str, Counts] = {c: Counts() for c in CATEGORIES}
    repos: list[RepoResult] = []
    evaluated = 0
    skipped: list[str] = []

    for label_file in sorted((BENCH_DIR / "ground_truth").glob("*.json")):
        label = json.loads(label_file.read_text(encoding="utf-8"))
        name = label.get("name", label_file.stem)
        path = _scan_target(label)
        if path is None:
            skipped.append(name)
            continue
        evaluated += 1
        result = run_scan(path, resolve=False, vulns=False)
        detected = _detected_pairs(result.inventory.model_dump())
        truth = _truth_pairs(label.get("components", []))

        repo = RepoResult(name=name)
        for cat in CATEGORIES:
            det = {k for c, k in detected if c == cat}
            tru = {k for c, k in truth if c == cat}
            counts = Counts(tp=len(det & tru), fp=len(det - tru), fn=len(tru - det))
            per_category[cat].add(counts)
            repo.false_positives += [(cat, k) for k in sorted(det - tru)]
            repo.false_negatives += [(cat, k) for k in sorted(tru - det)]
        repos.append(repo)

    overall = Counts()
    for counts in per_category.values():
        overall.add(counts)

    return {
        "evaluated": evaluated,
        "skipped": skipped,
        "overall": _counts_dict(overall),
        "categories": {
            c: _counts_dict(per_category[c]) for c in CATEGORIES
            if per_category[c].tp + per_category[c].fp + per_category[c].fn
        },
        "repositories": [
            {"name": r.name, "false_positives": r.false_positives,
             "false_negatives": r.false_negatives}
            for r in repos
        ],
    }


def _scan_target(label: dict) -> Path | None:
    """Return a local path to scan for a label, or None to skip it."""
    local = label.get("local_path")
    if local:
        path = (BENCH_DIR / local).resolve()
        return path if path.exists() else None
    return None  # networked repos are documented in repos.yaml, not run offline


def _counts_dict(c: Counts) -> dict:
    return {
        "tp": c.tp, "fp": c.fp, "fn": c.fn,
        "precision": round(c.precision, 4),
        "recall": round(c.recall, 4),
        "f1": round(c.f1, 4),
    }


# ── report rendering ─────────────────────────────────────────────────────────


def render_markdown(report: dict) -> str:
    o = report["overall"]
    lines = [
        "# AIBOM Inspector — benchmark results",
        "",
        f"Repositories evaluated: **{report['evaluated']}**"
        + (f" (skipped: {', '.join(report['skipped'])})" if report["skipped"] else ""),
        "",
        f"**Overall — Precision {o['precision']:.2f} · Recall {o['recall']:.2f} · "
        f"F1 {o['f1']:.2f}** (TP {o['tp']} / FP {o['fp']} / FN {o['fn']})",
        "",
        "| Category | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for cat, c in report["categories"].items():
        lines.append(
            f"| {cat} | {c['tp']} | {c['fp']} | {c['fn']} | "
            f"{c['precision']:.2f} | {c['recall']:.2f} | {c['f1']:.2f} |"
        )
    fps = [(r["name"], fp) for r in report["repositories"] for fp in r["false_positives"]]
    fns = [(r["name"], fn) for r in report["repositories"] for fn in r["false_negatives"]]
    if fps:
        lines += ["", "## False positives", ""]
        lines += [f"- `{name}`: {cat} → `{key}`" for name, (cat, key) in fps]
    if fns:
        lines += ["", "## False negatives", ""]
        lines += [f"- `{name}`: {cat} → `{key}`" for name, (cat, key) in fns]
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="AIBOM Inspector benchmark")
    ap.add_argument("--json", type=Path, default=BENCH_DIR / "reports" / "latest.json")
    ap.add_argument("--md", type=Path, default=BENCH_DIR / "reports" / "latest.md")
    ap.add_argument("--min-f1", type=float, default=0.0, help="Fail below this overall F1.")
    ap.add_argument("--max-fp", type=int, default=-1, help="Fail above this total FP count.")
    args = ap.parse_args()

    report = evaluate_all()
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    args.md.write_text(render_markdown(report), encoding="utf-8")

    o = report["overall"]
    print(render_markdown(report))
    print(f"\nwrote {args.json} and {args.md}")

    if args.min_f1 and o["f1"] < args.min_f1:
        print(f"FAIL: overall F1 {o['f1']:.2f} < {args.min_f1}", file=sys.stderr)
        return 1
    if args.max_fp >= 0 and o["fp"] > args.max_fp:
        print(f"FAIL: total FP {o['fp']} > {args.max_fp}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
