"""Evaluate AIBOM detections against manually curated ground truth.

This harness is offline by default.  Public repositories must be checked out at
their pinned commits before evaluation; scanned code is never executed.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aibom.models.entities import Entity, EntityType, Model, Package, Service
from aibom.service import run_scan

_CATEGORIES = (
    "models",
    "services",
    "prompts",
    "agents",
    "tools",
    "mcp",
    "datasets",
    "model_files",
    "ai_packages",
)
_TYPE_TO_CATEGORY = {
    "model": "models",
    "service": "services",
    "prompt": "prompts",
    "agent": "agents",
    "tool": "tools",
    "mcp": "mcp",
    "dataset": "datasets",
    "model_file": "model_files",
    "ai_package": "ai_packages",
    "package": "ai_packages",
}


@dataclass(frozen=True)
class ExpectedComponent:
    category: str
    name: str
    file: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class PredictedComponent:
    category: str
    name: str
    locations: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None


def evaluate_case(ground_truth: dict[str, Any], checkout: str | Path) -> dict[str, Any]:
    """Scan one checkout and compare it with one validated ground-truth document."""
    _validate_ground_truth(ground_truth)
    expected = [_expected_component(raw) for raw in ground_truth["components"]]
    predictions = _predictions(run_scan(checkout).inventory.entities)
    matched_expected, matched_predictions = _match(expected, predictions)

    false_negatives = [
        _expected_to_dict(component)
        for index, component in enumerate(expected)
        if index not in matched_expected
    ]
    false_positives = [
        _prediction_to_dict(component)
        for index, component in enumerate(predictions)
        if index not in matched_predictions
    ]

    categories: dict[str, dict[str, Any]] = {}
    for category in _CATEGORIES:
        expected_indices = {i for i, item in enumerate(expected) if item.category == category}
        prediction_indices = {i for i, item in enumerate(predictions) if item.category == category}
        metrics = _metrics(
            len(expected_indices & matched_expected),
            len(prediction_indices - matched_predictions),
            len(expected_indices - matched_expected),
        )
        categories[category] = asdict(metrics)

    overall = _metrics(
        len(matched_expected),
        len(predictions) - len(matched_predictions),
        len(expected) - len(matched_expected),
    )
    return {
        "repository": ground_truth["repository"],
        "commit": ground_truth["commit"],
        "overall": asdict(overall),
        "categories": categories,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def evaluate_suite(cases: list[tuple[dict[str, Any], Path]]) -> dict[str, Any]:
    """Evaluate and micro-average a list of pinned repository cases."""
    repositories = [evaluate_case(ground_truth, checkout) for ground_truth, checkout in cases]
    overall = _sum_metrics([repo["overall"] for repo in repositories])
    categories = {
        category: asdict(_sum_metrics([repo["categories"][category] for repo in repositories]))
        for category in _CATEGORIES
    }
    return {
        "schema_version": 1,
        "repository_count": len(repositories),
        "overall": asdict(overall),
        "categories": categories,
        "repositories": repositories,
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render a compact benchmark report suitable for README/CI artifacts."""
    overall = report["overall"]
    lines = [
        "# AIBOM Inspector benchmark",
        "",
        f"Repositories evaluated: {report['repository_count']}",
        "",
        "| Category | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|",
        _metric_row("Overall", overall),
    ]
    for category in _CATEGORIES:
        lines.append(
            _metric_row(category.replace("_", " ").title(), report["categories"][category])
        )
    lines.extend(["", "## Errors", ""])
    any_errors = False
    for repository in report["repositories"]:
        error_types = (
            ("False positive", "false_positives"),
            ("False negative", "false_negatives"),
        )
        for label, key in error_types:
            for component in repository[key]:
                any_errors = True
                location = _component_location(component)
                lines.append(
                    f"- {label}: `{repository['repository']}` "
                    f"{component['category']} `{component['name']}`{location}"
                )
    if not any_errors:
        lines.append("No mismatches in the evaluated cases.")
    lines.append("")
    return "\n".join(lines)


def _predictions(entities: list[Entity]) -> list[PredictedComponent]:
    predictions: list[PredictedComponent] = []
    for entity in entities:
        category = _entity_category(entity)
        if category is None:
            continue
        locations = tuple(sorted({(item.file, item.line_start) for item in entity.source_evidence}))
        predictions.append(
            PredictedComponent(category=category, name=entity.name, locations=locations)
        )
    return sorted(predictions, key=lambda item: (item.category, item.name.lower()))


def _entity_category(entity: Entity) -> str | None:
    if isinstance(entity, Package):
        return "ai_packages" if entity.ai else None
    if isinstance(entity, Model) and (entity.formats or entity.provider == "local"):
        return "model_files"
    if isinstance(entity, Service) and entity.kind == "mcp":
        return "mcp"
    mapping = {
        EntityType.MODEL: "models",
        EntityType.DATASET: "datasets",
        EntityType.PROMPT: "prompts",
        EntityType.AGENT: "agents",
        EntityType.SERVICE: "services",
    }
    return mapping.get(entity.type)


def _match(
    expected: list[ExpectedComponent], predictions: list[PredictedComponent]
) -> tuple[set[int], set[int]]:
    matched_expected: set[int] = set()
    matched_predictions: set[int] = set()
    for expected_index, wanted in enumerate(expected):
        for prediction_index, actual in enumerate(predictions):
            if prediction_index in matched_predictions or not _matches(wanted, actual):
                continue
            matched_expected.add(expected_index)
            matched_predictions.add(prediction_index)
            break
    return matched_expected, matched_predictions


def _matches(expected: ExpectedComponent, predicted: PredictedComponent) -> bool:
    if expected.category != predicted.category:
        return False
    if _normalize(expected.name) != _normalize(predicted.name):
        return False
    if expected.file is None:
        return True
    for file, line in predicted.locations:
        if Path(file).as_posix().lower() != Path(expected.file).as_posix().lower():
            continue
        if expected.line is None or expected.line == line:
            return True
    return False


def _expected_component(raw: dict[str, Any]) -> ExpectedComponent:
    category = _TYPE_TO_CATEGORY.get(str(raw["type"]).lower())
    if category is None:
        raise ValueError(f"unsupported component type: {raw['type']}")
    return ExpectedComponent(
        category=category,
        name=str(raw["name"]),
        file=str(raw["file"]) if raw.get("file") is not None else None,
        line=int(raw["line"]) if raw.get("line") is not None else None,
    )


def _metrics(true_positives: int, false_positives: int, false_negatives: int) -> Metrics:
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    precision = true_positives / precision_denominator if precision_denominator else None
    recall = true_positives / recall_denominator if recall_denominator else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return Metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=round(precision, 4) if precision is not None else None,
        recall=round(recall, 4) if recall is not None else None,
        f1=round(f1, 4) if f1 is not None else None,
    )


def _sum_metrics(items: list[dict[str, Any]]) -> Metrics:
    return _metrics(
        sum(int(item["true_positives"]) for item in items),
        sum(int(item["false_positives"]) for item in items),
        sum(int(item["false_negatives"]) for item in items),
    )


def _validate_ground_truth(document: dict[str, Any]) -> None:
    for field in ("repository", "commit", "components"):
        if field not in document:
            raise ValueError(f"ground truth missing required field: {field}")
    if not isinstance(document["components"], list):
        raise ValueError("ground truth components must be a list")
    for index, component in enumerate(document["components"]):
        if not isinstance(component, dict) or not {"type", "name"} <= component.keys():
            raise ValueError(f"ground truth component {index} requires type and name")


def _normalize(value: str) -> str:
    return value.strip().casefold()


def _expected_to_dict(component: ExpectedComponent) -> dict[str, Any]:
    return asdict(component)


def _prediction_to_dict(component: PredictedComponent) -> dict[str, Any]:
    return {
        "category": component.category,
        "name": component.name,
        "locations": [{"file": file, "line": line} for file, line in component.locations],
    }


def _metric_row(label: str, metrics: dict[str, Any]) -> str:
    return (
        f"| {label} | {_format_metric(metrics['precision'])} | "
        f"{_format_metric(metrics['recall'])} | {_format_metric(metrics['f1'])} | "
        f"{metrics['true_positives']} | "
        f"{metrics['false_positives']} | {metrics['false_negatives']} |"
    )


def _format_metric(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def _component_location(component: dict[str, Any]) -> str:
    if component.get("file"):
        line = f":{component['line']}" if component.get("line") else ""
        return f" at `{component['file']}{line}`"
    locations = component.get("locations", [])
    if locations:
        first = locations[0]
        return f" at `{first['file']}:{first['line']}`"
    return ""


def _load_cases(ground_truth_dir: Path, project_root: Path) -> list[tuple[dict[str, Any], Path]]:
    cases: list[tuple[dict[str, Any], Path]] = []
    for path in sorted(ground_truth_dir.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        _validate_ground_truth(document)
        local_path = document.get("local_path")
        if local_path is None:
            raise ValueError(f"{path}: local_path is required for offline evaluation")
        checkout = (project_root / str(local_path)).resolve()
        if not checkout.exists():
            raise FileNotFoundError(
                f"pinned checkout not found for {document['repository']}: {checkout}"
            )
        cases.append((document, checkout))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ground-truth-dir",
        type=Path,
        default=Path(__file__).parent / "ground_truth",
    )
    parser.add_argument("--project-root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--json", type=Path, default=Path(__file__).parent / "reports/latest.json")
    parser.add_argument(
        "--markdown", type=Path, default=Path(__file__).parent / "reports/latest.md"
    )
    args = parser.parse_args()

    report = evaluate_suite(_load_cases(args.ground_truth_dir, args.project_root))
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.markdown.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    print(
        f"evaluated {report['repository_count']} repositories: "
        f"precision={_format_metric(report['overall']['precision'])} "
        f"recall={_format_metric(report['overall']['recall'])} "
        f"f1={_format_metric(report['overall']['f1'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
