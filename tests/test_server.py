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

TS_BASELINE = FIXTURE.parent / "impact-demo-ts-baseline"
TS_CANDIDATE = FIXTURE.parent / "impact-demo-ts"


@contextmanager
def _fake_clone(_url: str, *, ref: str | None = None) -> Iterator[Path]:
    """Stand in for git; ``ref`` selects a revision the way a real clone would."""
    if ref == "drift-candidate":
        yield TS_CANDIDATE
    elif ref == "drift-baseline":
        yield TS_BASELINE
    else:
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
    assert data["analysis_scope"]["risk_context"] == "production"
    assert data["analysis_scope"]["excluded_non_production_entities"] == 0
    assert data["analysis_scope"]["production_ai_components"] > 0

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


def test_built_in_demo_is_offline_and_shows_blast_radius(client: TestClient) -> None:
    resp = client.post("/api/demo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["repo_url"] == "built-in://impact-demo"
    assert data["stats"]["clone_ms"] is None
    assert data["graph"]["impact_paths"]
    path = data["graph"]["impact_paths"][0]
    assert path["source_kind"] == "http_request"
    assert path["tool_names"] == ["run_diagnostic"]
    assert path["severity"] == "critical"
    assert path["capabilities"][0]["operation"] == "subprocess.run"
    assert any(item["rule_id"] == "AIBOM-IMPACT-001" for item in data["findings"])

    report = client.post("/api/demo/report")
    assert report.status_code == 200
    assert "Potential blast radius" in report.text


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


# --- behavioral drift parity with `aibom diff` ------------------------------


@pytest.mark.parametrize("language", ["python", "typescript"])
def test_built_in_drift_demo_reports_identical_components(
    client: TestClient, language: str
) -> None:
    """The headline claim, offline: same parts, new blast radius."""
    resp = client.post(f"/api/diff/demo?language={language}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["components_identical"] is True
    kinds = {change["kind"] for change in body["drift"]["changes"]}
    assert "impact_path_added" in kinds
    critical = [c for c in body["drift"]["changes"] if c["severity"] == "critical"]
    assert critical, body["drift"]["changes"]
    assert critical[0]["after_evidence"], "a drift claim must carry file/line evidence"


def test_diff_compares_two_revisions(client: TestClient) -> None:
    resp = client.post(
        "/api/diff",
        json={
            "repo_url": "https://github.com/owner/repo",
            "base_ref": "drift-baseline",
            "head_ref": "drift-candidate",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["components_identical"] is True
    assert body["baseline"]["findings"] == 0
    assert body["candidate"]["findings"] >= 1
    assert "impact_path_added" in {c["kind"] for c in body["drift"]["changes"]}


def test_diff_rejects_a_disallowed_host(client: TestClient) -> None:
    resp = client.post(
        "/api/diff",
        json={
            "repo_url": "https://internal.example.com/o/r",
            "base_ref": "main",
            "head_ref": "dev",
        },
    )
    assert resp.status_code == 400
    assert "not allowed" in resp.json()["detail"]


def test_diff_demo_rejects_an_unknown_language(client: TestClient) -> None:
    """An unknown language falls back to Python rather than 500-ing."""
    resp = client.post("/api/diff/demo?language=cobol")
    assert resp.status_code == 200


# --- export parity with the CLI ---------------------------------------------


def test_sarif_endpoint_matches_cli_output(client: TestClient) -> None:
    resp = client.post("/api/sarif", json={"repo_url": "https://github.com/o/r"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "2.1.0"
    assert body["runs"][0]["tool"]["driver"]["name"] == "AIBOM Inspector"


def test_demo_sarif_endpoint_is_offline(client: TestClient) -> None:
    resp = client.post("/api/demo/sarif")
    assert resp.status_code == 200
    rules = resp.json()["runs"][0]["tool"]["driver"]["rules"]
    assert any(rule["id"] == "AIBOM-IMPACT-001" for rule in rules)
