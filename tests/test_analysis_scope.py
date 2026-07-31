"""Production-risk scope and scanner self-reference regression tests."""

from __future__ import annotations

from pathlib import Path

from aibom import __version__
from aibom.collectors.repo import RepoCollector
from aibom.graph import build_graph
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.analysis import SourceContext
from aibom.models.entities import EntityType, Model
from aibom.report.html import render_html
from aibom.risk.engine import evaluate
from aibom.risk.scoring import score_findings
from aibom.service import run_scan


def _collect(target: Path) -> Inventory:
    inventory = Inventory(
        metadata=ScanMetadata(tool_version=__version__, target=str(target))
    )
    RepoCollector(target).collect(inventory)
    return inventory


def test_python_detector_patterns_and_explanations_are_not_runtime_signals(
    tmp_path: Path,
) -> None:
    (tmp_path / "scanner.py").write_text(
        "import re\n"
        "_RULE = re.compile(r'trust_remote_code\\\\s*=\\\\s*True')\n"
        "MESSAGE = '`trust_remote_code=True` enables arbitrary code execution'\n"
        "SOURCE_FIXTURE = 'api_key = \"sk-abcdef0123456789ABCDEF0123\"\\n'\n",
        encoding="utf-8",
    )
    inventory = _collect(tmp_path)
    assert not inventory.signals_of("trust_remote_code")
    assert not inventory.signals_of("hardcoded_secret")


def test_actual_python_security_settings_still_emit_ast_signals(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from transformers import AutoModel\n"
        'api_key = "sk-abcdef0123456789ABCDEF0123"\n'
        "model = AutoModel.from_pretrained(\n"
        '    "acme/model", trust_remote_code=True\n'
        ")\n",
        encoding="utf-8",
    )
    inventory = _collect(tmp_path)
    trust = inventory.signals_of("trust_remote_code")
    secrets = inventory.signals_of("hardcoded_secret")
    assert len(trust) == 1
    assert len(secrets) == 1
    assert trust[0].source_evidence[0].detector_id == "python.security-signals.ast"
    assert secrets[0].source_evidence[0].snippet == "api_key = <redacted>"
    assert "sk-abcdef0123456789ABCDEF0123" not in inventory.model_dump_json()


def test_non_production_components_remain_in_inventory_but_not_risk_or_graph(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "tests" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / "bad.py").write_text(
        "from transformers import AutoModel\n"
        "model = AutoModel.from_pretrained(\n"
        '    "acme-ai/llama-7b-hf", trust_remote_code=True\n'
        ")\n",
        encoding="utf-8",
    )
    (fixture / "weights.pkl").write_bytes(b"static test fixture")

    result = run_scan(tmp_path)
    models = [
        entity
        for entity in result.inventory.by_type(EntityType.MODEL)
        if isinstance(entity, Model)
    ]
    assert models
    assert all(entity.source_contexts == [SourceContext.TEST] for entity in models)
    assert result.findings == []
    assert result.score.overall == 100
    assert build_graph(result.inventory, result.findings)["nodes"] == []

    html = render_html(result.inventory, result.findings, result.score)
    assert "No production AI components detected" in html
    assert "acme-ai/llama-7b-hf" in html


def test_direct_risk_engine_evaluation_applies_production_scope() -> None:
    inventory = Inventory(
        metadata=ScanMetadata(tool_version=__version__, target="/repo")
    )
    inventory.add_entity(
        Model(
            name="fixture.pkl",
            provider="local",
            formats=["pkl"],
            source_contexts=[SourceContext.TEST],
        )
    )
    findings = evaluate(inventory)
    assert findings == []
    assert score_findings(findings).overall == 100
