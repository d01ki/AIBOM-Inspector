"""Tests for the FastAPI backend.

The real cloner is overridden with one that yields the bundled fixture, so these
run fully offline and never touch git or the network.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aibom.server.app import create_app, get_cloner
from aibom.server.clone import CloneError, normalize_repo_url
from tests.conftest import FIXTURE


@contextmanager
def _fake_clone(_url: str) -> Iterator[Path]:
    yield FIXTURE


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    app.dependency_overrides[get_cloner] = lambda: _fake_clone
    return TestClient(app)


def test_health(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_scan_returns_full_payload(client: TestClient) -> None:
    resp = client.post(
        "/api/scan",
        json={"repo_url": "https://github.com/d01ki/AIBOM-Inspector",
              "resolve": False, "vulns": False},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["repo_url"].startswith("https://github.com/")
    assert data["metadata"]["target"] == "https://github.com/d01ki/AIBOM-Inspector.git"
    assert data["counts"]["model"] >= 4
    assert data["score"]["overall"] <= 100
    assert "grade" in data["score"]
    assert data["cyclonedx"]["bomFormat"] == "CycloneDX"

    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert {"TDR-001", "TDR-003", "TDR-009"} <= rule_ids

    stats = data["stats"]
    assert stats["files_scanned"] > 0
    assert stats["clone_ms"] is not None  # API scans time the clone step

    graph = data["graph"]
    assert len(graph["nodes"]) == len(data["inventory"]["entities"])
    node_ids = {n["id"] for n in graph["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in graph["edges"])


def test_report_returns_html(client: TestClient) -> None:
    resp = client.post(
        "/api/report",
        json={"repo_url": "https://github.com/d01ki/AIBOM-Inspector",
              "resolve": False, "vulns": False},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.text.startswith("<!DOCTYPE html>")
    assert "TDR-001" in resp.text


def test_invalid_url_is_rejected(client: TestClient) -> None:
    resp = client.post("/api/scan", json={"repo_url": "not-a-url"})
    assert resp.status_code == 400
    assert "invalid repository URL" in resp.json()["detail"]


def test_disallowed_host_is_rejected(client: TestClient) -> None:
    resp = client.post("/api/scan", json={"repo_url": "https://evil.internal/owner/repo"})
    assert resp.status_code == 400
    assert "not allowed" in resp.json()["detail"]


# ── URL validation unit tests ────────────────────────────────────────────────


def test_normalize_accepts_github() -> None:
    assert normalize_repo_url("https://github.com/owner/repo") == \
        "https://github.com/owner/repo.git"
    assert normalize_repo_url("https://github.com/owner/repo.git/") == \
        "https://github.com/owner/repo.git"


@pytest.mark.parametrize(
    "bad",
    [
        "http://github.com/o/r",            # not https
        "https://github.com/only-owner",    # missing repo
        "git@github.com:o/r.git",           # scp form
        "https://internal.host/o/r",        # host not allowed
        "https://github.com/o/r; rm -rf /",  # injection-ish
        "",
    ],
)
def test_normalize_rejects_bad_urls(bad: str) -> None:
    with pytest.raises(CloneError):
        normalize_repo_url(bad)


def test_enrichment_defaults_are_on() -> None:
    """The API has network by definition; both enrichments default to on."""
    from aibom.server.app import ScanRequest

    req = ScanRequest(repo_url="https://github.com/o/r")
    assert req.resolve is True
    assert req.vulns is True
