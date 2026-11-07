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
    "affected": [{"ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "4.41.0"}]}]}],
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
        def __init__(self, *_a: Any, **_k: Any) -> None:
            from aibom.inventory import VulnLookup

            self.coverage = VulnLookup(requested=True, status="complete", queried=1)

        def map(self, _inv: Any) -> list[Finding]:
            return [vuln_finding]

    monkeypatch.setattr(service, "HuggingFaceResolver", FakeHFResolver)
    monkeypatch.setattr(service, "OSVMapper", FakeMapper)

    result = service.run_scan(tmp_path, resolve=True)
    assert any(f.rule_id == "GHSA-test" for f in result.findings)
    # critical vuln => integrity category takes the hit
    integrity = next(c for c in result.score.categories if c.category is RiskCategory.INTEGRITY)
    assert integrity.score <= 60


# --- review backlog #34 / #35 -------------------------------------------------

def _pinned(name: str = "certifi", version: str = "2023.7.22") -> Package:
    return Package(name=name, ecosystem="PyPI", version=version,
                   version_pinned=True, source_evidence=[_ev()])


def _scan(pkg: Package, vulns: list[dict[str, Any]]) -> list[Any]:
    client = FakeOSV({(pkg.name, "PyPI", pkg.version or ""): vulns})
    return OSVMapper(client).map(_inv(pkg))


_GIT_AND_ECOSYSTEM = {
    "id": "PYSEC-2024-230",
    "summary": "certifi removes GLOBALTRUST root certificate",
    "affected": [{
        "package": {"name": "certifi", "ecosystem": "PyPI"},
        "ranges": [
            {"type": "GIT", "repo": "https://github.com/certifi/python-certifi",
             "events": [{"introduced": "0"},
                        {"fixed": "bd8153872e9c6fc98f4023df9c2deaffea2fa463"}]},
            {"type": "ECOSYSTEM",
             "events": [{"introduced": "2021.5.30"}, {"fixed": "2024.7.4"}]},
        ],
    }],
}


def test_git_range_commit_is_never_offered_as_a_release() -> None:
    [finding] = _scan(_pinned(), [_GIT_AND_ECOSYSTEM])
    assert "bd8153872e9c" not in finding.remediation
    assert finding.advisory.fixed_version == "2024.7.4"
    assert "2024.7.4" in finding.remediation
    assert finding.advisory.affected_ranges == [">=2021.5.30, <2024.7.4"]


def test_only_a_git_range_means_fixed_version_unknown() -> None:
    vuln = {
        "id": "PYSEC-2024-60", "summary": "idna DoS",
        "affected": [{"package": {"name": "idna", "ecosystem": "PyPI"}, "ranges": [
            {"type": "GIT", "events": [
                {"introduced": "0"}, {"fixed": "1d365e17e10d72d0b7876316fc7b9ca0eebdd38d"}]},
        ]}],
    }
    [finding] = _scan(_pinned("idna", "3.4"), [vuln])
    assert finding.advisory.fixed_version is None
    assert "1d365e17" not in finding.remediation
    assert "No fixed PyPI release is recorded" in finding.remediation
    assert "https://osv.dev/vulnerability/PYSEC-2024-60" in finding.remediation


def test_fix_on_the_installed_release_line_is_preferred() -> None:
    vuln = {"id": "GHSA-aaaa-bbbb-cccc", "affected": [{"ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.8"},
                                          {"introduced": "3.0.0"}, {"fixed": "3.0.3"}]},
    ]}]}
    [finding] = _scan(_pinned("werkzeug", "3.0.1"), [vuln])
    assert finding.advisory.fixed_version == "3.0.3"


def test_fix_for_another_package_in_the_advisory_is_ignored() -> None:
    vuln = {"id": "GHSA-dddd-eeee-ffff", "affected": [
        {"package": {"name": "other-pkg", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]},
        {"package": {"name": "H11", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.16.0"}]}]},
    ]}
    [finding] = _scan(_pinned("h11", "0.14.0"), [vuln])
    assert finding.advisory.fixed_version == "0.16.0"


_GHSA = {
    "id": "GHSA-vqfr-h8mv-ghfj", "aliases": ["CVE-2025-43859"],
    "summary": "h11 accepts some malformed Chunked-Encoding bodies",
    "modified": "2025-05-01T00:00:00Z",
    "database_specific": {"severity": "CRITICAL"},
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
    "affected": [{"package": {"name": "h11", "ecosystem": "PyPI"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.16.0"}]}]}],
}
_PYSEC = {
    "id": "PYSEC-2026-348", "aliases": ["CVE-2025-43859", "GHSA-vqfr-h8mv-ghfj"],
    "summary": "h11 request smuggling",
    "modified": "2026-01-02T00:00:00Z",
    "affected": [{"package": {"name": "h11", "ecosystem": "PyPI"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.16.0"}]}]}],
}


def test_aliased_advisories_become_one_finding_with_every_id() -> None:
    findings = _scan(_pinned("h11", "0.14.0"), [_PYSEC, _GHSA])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "GHSA-vqfr-h8mv-ghfj"  # GHSA preferred as the primary id
    assert set(finding.advisory.ids) == {
        "GHSA-vqfr-h8mv-ghfj", "PYSEC-2026-348", "CVE-2025-43859"}
    assert finding.advisory.urls == [
        "https://osv.dev/vulnerability/GHSA-vqfr-h8mv-ghfj",
        "https://osv.dev/vulnerability/PYSEC-2026-348",
    ]
    assert finding.advisory.modified == "2026-01-02T00:00:00Z"
    assert "PYSEC-2026-348" in finding.description


def test_merged_severity_is_the_highest_rating_with_its_sources() -> None:
    [finding] = _scan(_pinned("h11", "0.14.0"), [_PYSEC, _GHSA])
    assert finding.severity is Severity.CRITICAL
    by_source = {(s.advisory_id, s.source): s for s in finding.advisory.severity_sources}
    ghsa = by_source[("GHSA-vqfr-h8mv-ghfj", "database_specific.severity")]
    assert ghsa.severity is Severity.CRITICAL
    cvss = by_source[("GHSA-vqfr-h8mv-ghfj", "CVSS_V3")]
    assert cvss.score == 9.1 and cvss.severity is Severity.CRITICAL
    # PYSEC carries no rating: recorded as unrated, not as a medium vote.
    assert by_source[("PYSEC-2026-348", "none")].severity is None


def test_unrelated_advisories_stay_separate() -> None:
    other = {"id": "GHSA-zzzz-zzzz-zzzz", "summary": "other", "affected": []}
    findings = _scan(_pinned("h11", "0.14.0"), [_GHSA, other])
    assert sorted(f.rule_id for f in findings) == ["GHSA-vqfr-h8mv-ghfj", "GHSA-zzzz-zzzz-zzzz"]


def test_withdrawn_advisory_is_dropped() -> None:
    withdrawn = dict(_GHSA, withdrawn="2025-06-01T00:00:00Z")
    assert _scan(_pinned("h11", "0.14.0"), [withdrawn]) == []


def test_unrated_advisory_says_how_its_severity_was_chosen() -> None:
    [finding] = _scan(_pinned("h11", "0.14.0"), [_PYSEC])
    assert finding.severity is Severity.MEDIUM
    assert "no advisory rates it" in finding.advisory.severity_rule


def test_failed_lookup_is_recorded_not_reported_as_clean() -> None:
    from aibom.vuln.osv import VulnLookupError

    class Down:
        def query(self, *_a: Any) -> list[dict[str, Any]]:
            raise VulnLookupError("timeout")

    unpinned = Package(name="flask", ecosystem="PyPI", version=">=2",
                       version_pinned=False, source_evidence=[_ev()])
    mapper = OSVMapper(Down())
    assert mapper.map(_inv(_pinned(), unpinned)) == []
    cov = mapper.coverage
    assert cov.status == "failed" and cov.failed == 1 and cov.queried == 0
    assert cov.not_queried_unpinned == 1


def test_lookup_over_the_query_cap_is_partial() -> None:
    mapper = OSVMapper(FakeOSV({}), max_queries=1)
    mapper.map(_inv(_pinned("a", "1.0"), _pinned("b", "1.0")))
    assert mapper.coverage.status == "partial"
    assert mapper.coverage.queried == 1 and mapper.coverage.not_queried_over_limit == 1


def test_osv_client_raises_on_transport_error(monkeypatch: Any) -> None:
    import urllib.request

    import pytest

    from aibom.vuln.osv import OSVClient, VulnLookupError

    def boom(*_a: Any, **_k: Any) -> Any:
        raise TimeoutError("slow")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(VulnLookupError):
        OSVClient().query("h11", "PyPI", "0.14.0")


def test_cvss3_base_scores_match_the_specification_examples() -> None:
    from aibom.vuln.osv import cvss3_base_score

    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("CVSS:4.0/AV:N") is None
    assert cvss3_base_score("CVSS:3.1/AV:N") is None


def test_recommended_upgrade_clears_every_advisory() -> None:
    from aibom.vuln.osv import recommended_upgrade

    assert recommended_upgrade(["2.2.3", "2.10.0", None, "2.9"]) == "2.10.0"
    assert recommended_upgrade([None]) is None


def test_ignore_rule_matches_any_alias(monkeypatch: Any, tmp_path: Any) -> None:
    import aibom.service as service

    (tmp_path / "requirements.txt").write_text("h11==0.14.0\n", encoding="utf-8")
    monkeypatch.setattr(service, "OSVMapper",
                        lambda: OSVMapper(FakeOSV({("h11", "PyPI", "0.14.0"): [_GHSA]})))
    kept = service.run_scan(tmp_path, vulns=True)
    assert any(f.rule_id == "GHSA-vqfr-h8mv-ghfj" for f in kept.findings)
    assert kept.inventory.stats.vuln_lookup.status == "complete"
    dropped = service.run_scan(tmp_path, vulns=True, ignore_rules=["CVE-2025-43859"])
    assert not any(f.rule_id == "GHSA-vqfr-h8mv-ghfj" for f in dropped.findings)
