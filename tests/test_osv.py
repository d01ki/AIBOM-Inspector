"""Tests for OSV vulnerability mapping (fake client — no network)."""

from __future__ import annotations

from typing import Any

from aibom import __version__
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import Package
from aibom.models.evidence import Evidence
from aibom.models.findings import RiskCategory, Severity
from aibom.vuln.osv import OSVMapper


def _ev() -> Evidence:
    return Evidence(
        file="requirements.txt", line_start=1, line_end=1, snippet="transformers==4.40.0",
        matched_pattern="pypi-dependency", confidence=0.9,
    )


def _inv(*pkgs: Package) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/x"))
    for p in pkgs:
        inv.add_entity(p)
    return inv


class FakeOSV:
    def __init__(self, table: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
        self.table = table
        self.calls: list[tuple[str, str, str]] = []

    def query(self, name: str, ecosystem: str, version: str) -> list[dict[str, Any]]:
        self.calls.append((name, ecosystem, version))
        return self.table.get((name, ecosystem, version), [])


_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Deserialization of untrusted data in transformers",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.41.0"}]}]}],
}


def test_maps_pinned_package_to_finding() -> None:
    pkg = Package(name="transformers", ecosystem="PyPI", version="4.40.0",
                  version_pinned=True, source_evidence=[_ev()])
    client = FakeOSV({("transformers", "PyPI", "4.40.0"): [_VULN]})
    findings = OSVMapper(client).map(_inv(pkg))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "GHSA-xxxx-yyyy-zzzz"
    assert f.severity is Severity.HIGH
    assert f.category is RiskCategory.INTEGRITY
    assert f.entity_name == "transformers"
    assert "4.41.0" in f.remediation
    assert f.source_evidence and f.source_evidence[0].file == "requirements.txt"


def test_unpinned_package_is_not_queried() -> None:
    pkg = Package(name="torch", ecosystem="PyPI", version="2.0",
                  version_pinned=False, source_evidence=[_ev()])
    client = FakeOSV({})
    findings = OSVMapper(client).map(_inv(pkg))
    assert findings == []
    assert client.calls == []  # never queried without an exact pin


def test_severity_defaults_to_medium_when_absent() -> None:
    vuln = {"id": "CVE-2024-0001", "summary": "x", "affected": []}
    pkg = Package(name="openai", ecosystem="PyPI", version="1.0.0",
                  version_pinned=True, source_evidence=[_ev()])
    client = FakeOSV({("openai", "PyPI", "1.0.0"): [vuln]})
    findings = OSVMapper(client).map(_inv(pkg))
    assert findings[0].severity is Severity.MEDIUM


def test_no_vulns_no_findings() -> None:
    pkg = Package(name="openai", ecosystem="PyPI", version="1.0.0",
                  version_pinned=True, source_evidence=[_ev()])
    assert OSVMapper(FakeOSV({})).map(_inv(pkg)) == []


def test_offline_client_makes_no_request() -> None:
    from aibom.vuln.osv import OSVClient

    # offline must short-circuit before any network call
    assert OSVClient(offline=True).query("transformers", "PyPI", "4.40.0") == []


def test_service_resolve_wires_osv(monkeypatch: Any, tmp_path: Any) -> None:
    """run_scan(resolve=True) should fold OSV findings in and re-score — verified
    with fakes so no network is used."""
    import aibom.service as service
    from aibom.models.findings import Finding

    (tmp_path / "requirements.txt").write_text("transformers==4.40.0\n", encoding="utf-8")

    class FakeHFResolver:
        def __init__(self, *_a: Any, **_k: Any) -> None: ...
        def resolve(self, _inv: Any) -> None: ...

    vuln_finding = Finding(
        rule_id="GHSA-test", title="v", severity=Severity.CRITICAL,
        category=RiskCategory.INTEGRITY, description="d", remediation="r",
        source_evidence=[_ev()],
    )

    class FakeMapper:
        def __init__(self, *_a: Any, **_k: Any) -> None: ...
        def map(self, _inv: Any) -> list[Finding]:
            return [vuln_finding]

    monkeypatch.setattr(service, "HuggingFaceResolver", FakeHFResolver)
    monkeypatch.setattr(service, "OSVMapper", FakeMapper)

    result = service.run_scan(tmp_path, resolve=True)
    assert any(f.rule_id == "GHSA-test" for f in result.findings)
    # critical vuln => integrity category takes the hit
    integrity = next(c for c in result.score.categories if c.category is RiskCategory.INTEGRITY)
    assert integrity.score <= 60
