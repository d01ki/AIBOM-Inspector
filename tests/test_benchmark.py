"""Tests for deterministic precision/recall benchmark reporting."""

from __future__ import annotations

import json
from pathlib import Path

from benchmark.evaluate import evaluate_case, evaluate_suite, render_markdown
from jsonschema import Draft202012Validator


def test_perfect_case_scores_one(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'from openai import OpenAI\nclient = OpenAI()\nclient.responses.create(model="gpt-4.1")\n',
        encoding="utf-8",
    )
    ground_truth = {
        "repository": "test/perfect",
        "commit": "abc123",
        "components": [
            {"type": "model", "name": "gpt-4.1", "file": "app.py", "line": 3},
            {"type": "service", "name": "openai", "file": "app.py", "line": 1},
        ],
    }

    result = evaluate_case(ground_truth, tmp_path)
    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["false_positives"] == []
    assert result["false_negatives"] == []


def test_mismatch_lists_false_positive_and_negative(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-actual")\n',
        encoding="utf-8",
    )
    ground_truth = {
        "repository": "test/mismatch",
        "commit": "abc123",
        "components": [{"type": "model", "name": "gpt-expected"}],
    }

    result = evaluate_case(ground_truth, tmp_path)
    assert result["overall"]["false_positives"] == 2  # model + detected service
    assert result["overall"]["false_negatives"] == 1
    suite = evaluate_suite([(ground_truth, tmp_path)])
    markdown = render_markdown(suite)
    assert "False positive" in markdown
    assert "False negative" in markdown


def test_checked_in_ground_truth_validates_against_schema() -> None:
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "benchmark/schemas/ground-truth.schema.json").read_text(encoding="utf-8")
    )
    document = json.loads(
        (root / "benchmark/ground_truth/vulnerable-ai-app.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(document)
    for public_path in sorted((root / "benchmark/ground_truth_public").glob("*.json")):
        Draft202012Validator(schema).validate(json.loads(public_path.read_text(encoding="utf-8")))


def test_checked_in_fixture_matches_ground_truth() -> None:
    root = Path(__file__).parents[1]
    document = json.loads(
        (root / "benchmark/ground_truth/vulnerable-ai-app.json").read_text(encoding="utf-8")
    )
    result = evaluate_case(document, root / document["local_path"])
    assert result["overall"] == {
        "true_positives": 20,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
