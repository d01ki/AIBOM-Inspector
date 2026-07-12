from __future__ import annotations

from aibom.models.entities import EntityType, Model
from aibom.models.evidence import Evidence


def _ev() -> Evidence:
    return Evidence(
        file="app.py", line_start=3, line_end=3, snippet="x", matched_pattern="test"
    )


def test_entity_id_is_deterministic() -> None:
    a = Model(name="bert-base-uncased", source_evidence=[_ev()])
    b = Model(name="bert-base-uncased", source_evidence=[_ev()])
    assert a.id == b.id
    assert a.id.startswith("model:")


def test_entity_id_differs_by_name() -> None:
    a = Model(name="bert-base-uncased", source_evidence=[_ev()])
    b = Model(name="gpt2", source_evidence=[_ev()])
    assert a.id != b.id


def test_natural_key_is_case_insensitive() -> None:
    a = Model(name="Org/Model", source_evidence=[_ev()])
    b = Model(name="org/model", source_evidence=[_ev()])
    assert a.natural_key() == b.natural_key()


def test_evidence_location_format() -> None:
    single = Evidence(file="a.py", line_start=5, line_end=5, snippet="x", matched_pattern="p")
    span = Evidence(file="a.py", line_start=5, line_end=9, snippet="x", matched_pattern="p")
    assert single.location() == "a.py:5"
    assert span.location() == "a.py:5-9"


def test_confidence_bounds_enforced() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Evidence(file="a", line_start=1, line_end=1, snippet="x", matched_pattern="p", confidence=2)


def test_model_defaults() -> None:
    m = Model(name="x", source_evidence=[_ev()])
    assert m.type is EntityType.MODEL
    assert m.revision_pinned is False
    assert m.formats == []
