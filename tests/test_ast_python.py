"""Tests for the AST detector's value resolution (Black Hat plan §7).

Recall: model/dataset names reached through variables, dicts, f-strings,
concatenation, and env-var defaults are detected. Precision: comments,
docstrings, imports, and non-model strings are not.
"""

from __future__ import annotations

from typing import Any

from aibom import __version__
from aibom.collectors.ast_python import detect_python
from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import Dataset, EntityType, Model


def _models(text: str) -> dict[str, Model]:
    return {
        e.name: e for e in detect_python(text, "a.py") if isinstance(e, Model)
    }


def _datasets(text: str) -> set[str]:
    return {e.name for e in detect_python(text, "a.py") if isinstance(e, Dataset)}


# ── recall: value resolution ─────────────────────────────────────────────────


def test_variable_model_name() -> None:
    m = _models('MODEL = "gpt-4.1"\nclient.responses.create(model=MODEL)\n')
    assert "gpt-4.1" in m
    assert m["gpt-4.1"].provider == "openai"
    assert m["gpt-4.1"].source_evidence[0].matched_pattern.endswith(":variable")


def test_from_pretrained_via_variable() -> None:
    m = _models('MODEL = "bert-base-uncased"\nAutoModel.from_pretrained(MODEL)\n')
    assert "bert-base-uncased" in m
    assert m["bert-base-uncased"].provider == "huggingface"


def test_dict_config_model() -> None:
    m = _models('CFG = {"model": "meta-llama/Llama-3.1-8B"}\n'
                'pipeline("text-generation", model=CFG["model"])\n')
    assert "meta-llama/Llama-3.1-8B" in m


def test_string_concat() -> None:
    m = _models('MODEL = "meta-llama/" + "Llama-3.1-8B"\n'
                'x.from_pretrained(MODEL)\n')
    assert "meta-llama/Llama-3.1-8B" in m


def test_fstring_fully_static() -> None:
    m = _models('V = "8B"\nMODEL = f"meta-llama/Llama-3.1-{V}"\n'
                'x.from_pretrained(MODEL)\n')
    assert "meta-llama/Llama-3.1-8B" in m


def test_env_default() -> None:
    m = _models('import os\nMODEL = os.getenv("MODEL_NAME", "gpt-4o")\n'
                'client.chat(model=MODEL)\n')
    assert "gpt-4o" in m
    assert m["gpt-4o"].source_evidence[0].matched_pattern.endswith(":env_default")


def test_dataset_via_variable() -> None:
    assert "imdb" in _datasets('NAME = "imdb"\nload_dataset(NAME)\n')


def test_literal_model_kwarg() -> None:
    assert "claude-sonnet-4-5" in _models('c.messages.create(model="claude-sonnet-4-5")\n')


# ── precision: must NOT fire ─────────────────────────────────────────────────


def test_unresolvable_env_is_not_guessed() -> None:
    # os.environ["X"] has no static default -> no detection (don't guess).
    assert not _models('import os\nMODEL = os.environ["MODEL_NAME"]\n'
                       'client.chat(model=MODEL)\n')


def test_comment_and_docstring_ignored() -> None:
    text = (
        '"""Example: client.chat(model="gpt-4o") in the docstring."""\n'
        '# MODEL = "gpt-4o"  a comment\n'
        'x = 1\n'
    )
    assert not _models(text)


def test_import_alone_is_not_a_model() -> None:
    assert not _models("from openai import OpenAI\nimport anthropic\n")


def test_non_model_kwarg_value_rejected() -> None:
    # A generic model= kwarg with a non-model-looking value must not fire.
    assert not _models('layer.build(model="sequential")\n')


def test_syntax_error_returns_empty() -> None:
    assert detect_python("def broken(:\n  pass\n", "a.py") == []


# ── integration through RepoCollector ────────────────────────────────────────


def test_repo_collector_resolves_variable_models(tmp_path: Any) -> None:
    (tmp_path / "svc.py").write_text(
        "import os\n"
        'DEFAULT = os.getenv("MODEL", "gpt-4o-mini")\n'
        "def answer(q):\n"
        "    return client.responses.create(model=DEFAULT, input=q)\n",
        encoding="utf-8",
    )
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    assert "gpt-4o-mini" in {m.name for m in inv.by_type(EntityType.MODEL)}


def test_ast_and_regex_dedupe(tmp_path: Any) -> None:
    # A literal from_pretrained is seen by both passes -> one entity, merged evidence.
    (tmp_path / "m.py").write_text(
        'AutoModel.from_pretrained("distilbert/distilbert-base-uncased")\n',
        encoding="utf-8",
    )
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    hits = [m for m in inv.by_type(EntityType.MODEL)
            if m.name == "distilbert/distilbert-base-uncased"]
    assert len(hits) == 1
