"""Tests for the FastAPI backend.

The real cloner is overridden with one that yields the bundled fixture, so these
run fully offline and never touch git or the network.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
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
    assert "Untrusted input reaches a bound tool" in report.text


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


@pytest.mark.parametrize("language", ["python", "typescript"])
def test_cross_file_demo_payload_carries_bom_scope_and_graph(
    client: TestClient, language: str
) -> None:
    body = client.post(f"/api/diff/demo?language={language}&scenario=cross-file").json()
    drift = body["drift"]
    assert drift["bom"]["identical"] is True
    assert drift["bom"]["compared_types"]
    assert drift["security_boundary_changed"] is True
    [added] = [c for c in drift["changes"] if c["kind"] == "impact_path_added"]
    assert added["evidence_level"] == "proven_static"
    nodes = added["details"]["nodes"]
    assert {node["role"] for node in nodes} >= {
        "source",
        "privileged_prompt",
        "model",
        "tool",
        "operation",
    }
    assert all(node["file"] for node in nodes if node["role"] != "model" or node["file"])
    assert body["baseline_paths"]["impact"] == []
    assert len(body["candidate_paths"]["impact"]) == 1


def test_cross_file_demo_fixed_revision_removes_the_path(client: TestClient) -> None:
    body = client.post("/api/diff/demo?scenario=cross-file&revision=fixed").json()
    kinds = {c["kind"] for c in body["drift"]["changes"]}
    assert "impact_path_removed" in kinds
    assert body["drift"]["security_boundary_changed"] is False


def test_diff_demo_rejects_an_unknown_scenario(client: TestClient) -> None:
    assert client.post("/api/diff/demo?scenario=nope").status_code == 400


def test_scan_and_demo_carry_agent_security(client: TestClient) -> None:
    scanned = client.post(
        "/api/scan",
        json={"repo_url": "https://github.com/d01ki/AIBOM-Inspector",
              "resolve": False, "vulns": False},
    ).json()
    demo = client.post("/api/demo").json()
    for payload in (scanned, demo):
        agents = payload["agent_security"]
        assert agents is not None and "error" not in agents
    assert demo["agent_security"]["agents"], "the sample app defines an Agents SDK agent"
    # No identity manifest in the sample: never guessed, always an unknown with a reason.
    assert "identity_unmapped" in {u["reason"] for u in demo["agent_security"]["unknowns"]}


@pytest.mark.parametrize(
    ("scenario", "gated_type"),
    [
        ("agent-privilege-drift", "permission_scope_expanded"),
        ("mcp-tool-exposure", "mcp_tool_exposure_added"),
    ],
)
def test_agent_drift_demo_is_offline_and_verifies_the_fix(
    client: TestClient, scenario: str, gated_type: str
) -> None:
    resp = client.post(f"/api/agent-drift/demo?scenario={scenario}")
    assert resp.status_code == 200
    data = resp.json()
    assert set(data["reports"]) == {"baseline", "candidate", "fixed"}
    introduced = data["introduced"]
    assert introduced["security_drift"] is True
    assert gated_type in {c["type"] for c in introduced["changes"] if c["gates"]}
    assert not [c for c in data["residual"]["changes"] if c["gates"]]
    assert data["scenario"]["changed"]


def test_agent_drift_demo_rejects_an_unknown_scenario(client: TestClient) -> None:
    assert client.post("/api/agent-drift/demo?scenario=nope").status_code == 400


def _assert_evidenced_graph(graph: dict) -> None:
    ids = {n["id"] for n in graph["nodes"]}
    assert graph["edges"], "a demo dependency map must not be empty"
    for edge in graph["edges"]:
        assert {edge["source"], edge["target"]} <= ids
        assert edge["evidence"], f"edge without evidence: {edge}"


@pytest.mark.parametrize("scenario", ["agent-privilege-drift", "mcp-tool-exposure"])
def test_agent_drift_demo_returns_a_dependency_map_per_revision(
    client: TestClient, scenario: str
) -> None:
    data = client.post(f"/api/agent-drift/demo?scenario={scenario}").json()
    for stage in ("baseline", "candidate", "fixed"):
        _assert_evidenced_graph(data["revisions"][stage]["graph"])


@pytest.mark.parametrize("language", ["python", "typescript"])
def test_compare_demo_returns_both_dependency_maps(client: TestClient, language: str) -> None:
    data = client.post(f"/api/diff/demo?language={language}&scenario=cross-file").json()
    for side in ("baseline", "candidate"):
        _assert_evidenced_graph(data[side]["graph"])


def test_sample_demo_graph_edges_all_cite_evidence(client: TestClient) -> None:
    _assert_evidenced_graph(client.post("/api/demo").json()["graph"])


# --- review backlog: headline, coverage notes, scan ref -----------------------

def test_scan_payload_leads_with_a_headline_and_coverage(client: TestClient) -> None:
    data = client.post(
        "/api/scan",
        json={"repo_url": "https://github.com/d01ki/AIBOM-Inspector",
              "resolve": False, "vulns": False},
    ).json()
    assert data["headline"]["status"] == "action_required"
    assert any("OSV" in note for note in data["coverage_notes"])
    assert data["stats"]["vuln_lookup"]["status"] == "not_requested"


def test_scan_passes_the_ref_to_the_cloner_and_records_it(client: TestClient) -> None:
    data = client.post(
        "/api/scan",
        json={"repo_url": "https://github.com/d01ki/AIBOM-Inspector", "ref": "drift-candidate",
              "resolve": False, "vulns": False},
    ).json()
    assert data["metadata"]["ref"] == "drift-candidate"
    assert data["metadata"]["target"].endswith("AIBOM-Inspector.git")


PRIV = Path(__file__).resolve().parents[1] / "examples" / "agent-privilege-drift"


def test_repository_compare_includes_agent_privileges_when_mapped() -> None:
    """Privilege drift is not demo-only: /api/diff runs it on a real checkout."""

    @contextmanager
    def clone(_url: str, *, ref: str | None = None) -> Iterator[Path]:
        yield PRIV / ("candidate" if ref == "head" else "baseline")

    app = create_app()
    app.dependency_overrides[get_cloner] = lambda: clone
    body = TestClient(app).post(
        "/api/diff",
        json={"repo_url": "https://github.com/o/r", "base_ref": "base", "head_ref": "head"},
    ).json()
    priv = body["agent_privileges"]
    assert priv["status"] == "evaluated"
    assert any(c["gates"] for c in priv["report"]["changes"])


def test_repository_compare_without_identity_manifest_is_not_evaluated(
    client: TestClient,
) -> None:
    body = client.post(
        "/api/diff",
        json={"repo_url": "https://github.com/o/r",
              "base_ref": "drift-baseline", "head_ref": "drift-candidate"},
    ).json()
    priv = body["agent_privileges"]
    assert priv["status"] == "not_evaluated"
    assert "aibom-identity.yaml" in priv["reason"]



def _stream_lines(resp: httpx.Response) -> list[dict[str, Any]]:
    return [json.loads(line) for line in resp.text.splitlines() if line.strip()]


def test_scan_stream_reports_each_stage_then_the_same_payload(client: TestClient) -> None:
    body = {"repo_url": "https://github.com/d01ki/AIBOM-Inspector",
            "resolve": False, "vulns": False}
    resp = client.post("/api/scan/stream", json=body)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    lines = _stream_lines(resp)
    stages = [line["stage"] for line in lines if "stage" in line]
    # Offline scan: no HF resolve or OSV lookup stage is claimed.
    assert stages == ["clone", "collect", "lockfiles", "link", "risk", "agents", "report"]
    assert "result" in lines[-1]
    plain = client.post("/api/scan", json=body).json()
    assert lines[-1]["result"].keys() == plain.keys()


def test_scan_stream_rejects_a_bad_url_before_streaming(client: TestClient) -> None:
    resp = client.post("/api/scan/stream", json={"repo_url": "not a url"})
    assert resp.status_code == 400


def test_scan_stream_reports_a_clone_failure_as_an_error_line() -> None:
    @contextmanager
    def failing_clone(_url: str, *, ref: str | None = None) -> Iterator[Path]:
        raise CloneError("ref not found")
        yield FIXTURE  # pragma: no cover

    app = create_app()
    app.dependency_overrides[get_cloner] = lambda: failing_clone
    resp = TestClient(app).post(
        "/api/scan/stream", json={"repo_url": "https://github.com/a/b", "ref": "nope"}
    )
    lines = _stream_lines(resp)
    assert lines[0] == {"stage": "clone"}
    assert lines[-1] == {"error": "ref not found", "status": 400}
    assert not any("result" in line for line in lines)


def test_closing_the_scan_stream_stops_the_work_at_the_next_stage() -> None:
    import asyncio
    import threading

    from aibom.server.app import ScanCancelled, ScanRequest, _stream_scan

    release, slot_released = threading.Event(), threading.Event()
    exited_with: list[type[BaseException] | None] = []

    @contextmanager
    def slow_clone(_url: str, *, ref: str | None = None) -> Iterator[Path]:
        release.wait(10)
        try:
            yield FIXTURE
        except BaseException as exc:
            exited_with.append(type(exc))
            raise
        exited_with.append(None)

    async def disconnect_after_first_line() -> None:
        stream = _stream_scan(ScanRequest(repo_url="https://github.com/a/b"), slow_clone,
                              release=slot_released.set)
        assert await anext(stream) == '{"stage": "clone"}\n'
        await stream.aclose()  # what Starlette does when the client goes away
        release.set()

    asyncio.run(disconnect_after_first_line())
    for _ in range(100):
        if exited_with:
            break
        threading.Event().wait(0.05)
    assert exited_with == [ScanCancelled]  # the scan never ran past "collect"
    assert slot_released.wait(10)  # a cancelled scan gives its slot back


def test_concurrent_clones_are_capped_and_the_overflow_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public instance must not start unbounded clones (resource exhaustion)."""
    import threading

    monkeypatch.setenv("AIBOM_MAX_CONCURRENT_SCANS", "1")
    entered, release = threading.Event(), threading.Event()

    @contextmanager
    def held_clone(_url: str, *, ref: str | None = None) -> Iterator[Path]:
        entered.set()
        release.wait(10)
        yield FIXTURE

    app = create_app()
    app.dependency_overrides[get_cloner] = lambda: held_clone
    client = TestClient(app)
    body = {"repo_url": "https://github.com/a/b", "resolve": False, "vulns": False}
    first: dict[str, int] = {}
    worker = threading.Thread(
        target=lambda: first.update(code=client.post("/api/scan", json=body).status_code)
    )
    worker.start()
    assert entered.wait(10)
    for route in ("/api/scan", "/api/scan/stream", "/api/report", "/api/sarif"):
        busy = client.post(route, json=body)
        assert busy.status_code == 503, route
        assert busy.headers.get("retry-after")
    busy = client.post("/api/diff", json={"repo_url": "https://github.com/a/b",
                                          "base_ref": "a", "head_ref": "b"})
    assert busy.status_code == 503
    release.set()
    worker.join(30)
    assert first["code"] == 200
    # The slot is released afterwards, including after a streamed scan.
    assert client.post("/api/scan/stream", json=body).status_code == 200
    assert client.post("/api/scan", json=body).status_code == 200


def test_responses_carry_security_headers(client: TestClient) -> None:
    api = client.get("/api/health")
    assert api.headers["x-content-type-options"] == "nosniff"
    assert api.headers["x-frame-options"] == "DENY"
    page = client.get("/")
    csp = page.headers["content-security-policy"]
    # No inline script may run, even if an escaping bug lets markup through.
    directives = dict(d.strip().split(" ", 1) for d in csp.split(";"))
    assert directives["script-src"] == "'self'"
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    report = client.post("/api/demo/report")
    assert "script-src 'self'" in report.headers["content-security-policy"]
