"""Tests for scan transparency stats — proof the scan actually read things."""

from __future__ import annotations

from aibom.service import run_scan
from tests.conftest import FIXTURE


def test_stats_populated_on_fixture_scan() -> None:
    result = run_scan(FIXTURE)
    st = result.inventory.stats
    assert st.files_scanned > 0
    assert st.bytes_scanned > 0
    assert st.duration_ms is not None and st.duration_ms >= 0
    assert any(m.endswith("requirements.txt") for m in st.manifests_parsed)
    assert st.clone_ms is None  # local scan: no clone step


def test_stats_serialize_in_inventory_json() -> None:
    result = run_scan(FIXTURE)
    dumped = result.inventory.model_dump()
    assert dumped["stats"]["files_scanned"] == result.inventory.stats.files_scanned
