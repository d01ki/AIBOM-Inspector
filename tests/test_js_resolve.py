"""Tests for lightweight JS/TS value resolution."""

from __future__ import annotations

from typing import Any

from aibom import __version__
from aibom.collectors.js_resolve import detect_javascript
from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import EntityType


def _models(text: str) -> dict[str, Any]:
    return {m.name: m for m in detect_javascript(text, "a.ts")}


def test_const_variable_model() -> None:
    m = _models('const MODEL = "gpt-4o";\nclient.responses.create({ model: MODEL });\n')
    assert "gpt-4o" in m
    assert m["gpt-4o"].source_evidence[0].matched_pattern == "js-model:variable"


def test_shorthand_property() -> None:
    m = _models('const model = "claude-sonnet-4-5";\n'
                'client.messages.create({ model });\n')
    assert "claude-sonnet-4-5" in m


def test_env_default_inline() -> None:
    m = _models('client.chat({ model: process.env.OPENAI_MODEL || "gpt-4.1" });\n')
    assert "gpt-4.1" in m
    assert m["gpt-4.1"].source_evidence[0].matched_pattern == "js-model:env_default"


def test_env_default_via_const() -> None:
    m = _models('const model = process.env.MODEL ?? "gpt-4o-mini";\n'
                'ai.generate({ model });\n')
    assert "gpt-4o-mini" in m


def test_hf_repo_via_variable() -> None:
    m = _models('const m = "meta-llama/Llama-3.1-8B";\nrunModel({ model: m });\n')
    assert "meta-llama/Llama-3.1-8B" in m


def test_unresolved_member_is_not_guessed() -> None:
    # model: config.model -> member access, not a bare var -> dropped.
    assert not _models('runModel({ model: config.model });\n')


def test_non_model_value_rejected() -> None:
    assert not _models('const mode = "sequential";\nbuild({ model: mode });\n')


def test_repo_collector_resolves_ts_model(tmp_path: Any) -> None:
    (tmp_path / "app.ts").write_text(
        'import OpenAI from "openai";\n'
        'const MODEL = process.env.MODEL || "gpt-4o";\n'
        'const client = new OpenAI();\n'
        'export const run = (q: string) =>\n'
        '  client.responses.create({ model: MODEL, input: q });\n',
        encoding="utf-8",
    )
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    models = {m.name for m in inv.by_type(EntityType.MODEL)}
    assert "gpt-4o" in models
    # the openai SDK import is still detected as a service
    assert "openai" in {s.name for s in inv.by_type(EntityType.SERVICE)}
