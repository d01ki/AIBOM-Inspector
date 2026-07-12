"""Golden-fixture and unit tests for the deterministic risk rules (TDR-001…010)."""

from __future__ import annotations

from typing import Any

from aibom import __version__
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import Dataset, Model
from aibom.models.evidence import Evidence
from aibom.models.findings import RiskCategory, Severity
from aibom.models.signals import RiskSignal
from aibom.risk.engine import evaluate
from aibom.risk.rules import (
    tdr_004_missing_model_card,
    tdr_005_license,
    tdr_006_unverified_author,
    tdr_007_hardcoded_secret,
    tdr_010_deprecated_model,
)


def _ev(file: str = "app.py", line: int = 1) -> Evidence:
    return Evidence(
        file=file, line_start=line, line_end=line, snippet="x",
        matched_pattern="test", confidence=0.9,
    )


def _inv(*entities: Any, signals: list[RiskSignal] | None = None) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/tmp/x"))
    for e in entities:
        inv.add_entity(e)
    for s in signals or []:
        inv.add_signal(s)
    return inv


def _rule_ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


# ── golden fixture (offline, no resolution) ──────────────────────────────────


def test_fixture_offline_findings(fixture_inventory: Inventory) -> None:
    ids = _rule_ids(evaluate(fixture_inventory))
    # Offline-detectable rules must all fire on the vulnerable fixture.
    assert {"TDR-001", "TDR-002", "TDR-003", "TDR-008", "TDR-009"} <= ids
    # Resolution-only rules must NOT fire without --resolve (no evidence to claim).
    assert not ({"TDR-004", "TDR-005", "TDR-006"} & ids)


def test_fixture_typosquat_targets_lookalike(fixture_inventory: Inventory) -> None:
    typos = [f for f in evaluate(fixture_inventory) if f.rule_id == "TDR-003"]
    assert {f.entity_name for f in typos} == {"acme-ai/llama-7b-hf"}
    assert all(f.severity is Severity.HIGH for f in typos)


def test_fixture_trust_remote_code_high(fixture_inventory: Inventory) -> None:
    trc = [f for f in evaluate(fixture_inventory) if f.rule_id == "TDR-009"]
    assert trc and all(f.severity is Severity.HIGH for f in trc)
    assert all(f.category is RiskCategory.CONFIGURATION for f in trc)


def test_every_finding_has_evidence(fixture_inventory: Inventory) -> None:
    for f in evaluate(fixture_inventory):
        assert f.source_evidence, f"{f.rule_id} has no evidence"


def test_findings_are_severity_ordered(fixture_inventory: Inventory) -> None:
    ranks = [f.severity.rank for f in evaluate(fixture_inventory)]
    assert ranks == sorted(ranks, reverse=True)


# ── unit tests for resolution-only / signal rules ────────────────────────────


def test_tdr004_missing_model_card() -> None:
    m = Model(name="a/b", provider="huggingface", resolved=True, has_model_card=False,
              source_evidence=[_ev()])
    assert tdr_004_missing_model_card(_inv(m))
    # unresolved -> no claim
    m2 = Model(name="a/c", provider="huggingface", source_evidence=[_ev()])
    assert not tdr_004_missing_model_card(_inv(m2))


def test_tdr005_unknown_and_nonspdx_license() -> None:
    unknown = Model(name="a/b", provider="huggingface", resolved=True, source_evidence=[_ev()])
    findings = tdr_005_license(_inv(unknown))
    assert findings and findings[0].severity is Severity.MEDIUM

    weird = Model(name="a/c", provider="huggingface", resolved=True,
                  license="my-custom-thing", source_evidence=[_ev()])
    findings = tdr_005_license(_inv(weird))
    assert findings and findings[0].severity is Severity.LOW

    ok = Model(name="a/d", provider="huggingface", resolved=True,
               license="apache-2.0", source_evidence=[_ev()])
    assert not tdr_005_license(_inv(ok))


def test_tdr006_low_downloads() -> None:
    m = Model(name="a/b", provider="huggingface", resolved=True, downloads=3,
              source_evidence=[_ev()])
    assert tdr_006_unverified_author(_inv(m))
    popular = Model(name="a/c", provider="huggingface", resolved=True, downloads=999_999,
                    source_evidence=[_ev()])
    assert not tdr_006_unverified_author(_inv(popular))


def test_tdr007_secret_near_ai_is_critical() -> None:
    model = Model(name="a/b", provider="huggingface", source_evidence=[_ev(file="app.py")])
    sig = RiskSignal(kind="hardcoded_secret", source_evidence=[_ev(file="app.py", line=9)])
    findings = tdr_007_hardcoded_secret(_inv(model, signals=[sig]))
    assert findings and findings[0].severity is Severity.CRITICAL


def test_tdr007_secret_elsewhere_is_high() -> None:
    model = Model(name="a/b", provider="huggingface", source_evidence=[_ev(file="model.py")])
    sig = RiskSignal(kind="hardcoded_secret", source_evidence=[_ev(file="config.py", line=2)])
    findings = tdr_007_hardcoded_secret(_inv(model, signals=[sig]))
    assert findings and findings[0].severity is Severity.HIGH


def test_tdr008_provenance_suppressed_when_present() -> None:
    resolved = Dataset(name="a/b", source="huggingface", provenance="hf author: acme",
                       source_evidence=[_ev()])
    assert not _rule_ids(evaluate(_inv(resolved))) & {"TDR-008"}


def test_tdr010_deprecated_model() -> None:
    m = Model(name="text-davinci-003", provider="openai", source_evidence=[_ev()])
    findings = tdr_010_deprecated_model(_inv(m))
    assert findings and findings[0].rule_id == "TDR-010"


def test_secret_signal_detected_by_collector(tmp_path: Any) -> None:
    from aibom.collectors.repo import RepoCollector

    src = tmp_path / "svc.py"
    src.write_text(
        'import openai\napi_key = "sk-abcdef0123456789ABCDEF0123"\n', encoding="utf-8"
    )
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    assert inv.signals_of("hardcoded_secret")
    assert {"TDR-007"} <= _rule_ids(evaluate(inv))


def test_env_lookup_is_not_a_secret(tmp_path: Any) -> None:
    from aibom.collectors.repo import RepoCollector

    src = tmp_path / "svc.py"
    src.write_text(
        'import os\napi_key = os.environ["OPENAI_API_KEY"]\n', encoding="utf-8"
    )
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    assert not inv.signals_of("hardcoded_secret")
