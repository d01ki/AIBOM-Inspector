"""OSV.dev client + mapper.

Queries the public OSV API for each pinned AI package and turns matching
advisories into :class:`~aibom.models.findings.Finding` objects. Constraints,
mirroring the resolvers:

* **Network-optional.** Any transport error yields no findings; a scan never
  fails because OSV is unreachable.
* **Precise.** Only exact (``==``) pinned versions are queried, so a finding
  means "this exact version is affected" — no range-guessing false positives.
* **Injectable.** ``OSVMapper`` takes a client, so tests use a fake.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol

from aibom.inventory import Inventory
from aibom.models.entities import EntityType, Package
from aibom.models.evidence import Evidence
from aibom.models.findings import Finding, RiskCategory, Severity

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 10.0

_SEVERITY_WORD = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class VulnClient(Protocol):
    def query(self, name: str, ecosystem: str, version: str) -> list[dict[str, Any]]: ...


class OSVClient:
    """Read-only OSV.dev client. Returns the ``vulns`` list, or ``[]`` on error."""

    def __init__(self, *, timeout: float = _TIMEOUT, offline: bool = False) -> None:
        self.timeout = timeout
        self.offline = offline

    def query(self, name: str, ecosystem: str, version: str) -> list[dict[str, Any]]:
        if self.offline:
            return []
        payload = json.dumps(
            {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        ).encode("utf-8")
        req = urllib.request.Request(
            _OSV_URL, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return []
        vulns = data.get("vulns") if isinstance(data, dict) else None
        return vulns if isinstance(vulns, list) else []


class OSVMapper:
    """Map pinned packages in an inventory to OSV vulnerability findings.

    Every pinned dependency is checked (the BOM is complete), AI packages
    first; ``max_queries`` bounds the total network calls on huge lockfiles.
    """

    def __init__(self, client: VulnClient | None = None, *, max_queries: int = 100) -> None:
        self.client = client or OSVClient()
        self.max_queries = max_queries

    def map(self, inventory: Inventory) -> list[Finding]:
        candidates = [
            pkg
            for pkg in inventory.by_type(EntityType.PACKAGE)
            if isinstance(pkg, Package)
            and pkg.version_pinned and pkg.version and pkg.ecosystem
        ]
        candidates.sort(key=lambda p: (not p.ai, p.name.lower()))
        findings: list[Finding] = []
        for pkg in candidates[: self.max_queries]:
            for vuln in self.client.query(pkg.name, pkg.ecosystem or "", pkg.version or ""):
                findings.append(_to_finding(pkg, vuln))
        return findings


def _to_finding(pkg: Package, vuln: dict[str, Any]) -> Finding:
    vid = str(vuln.get("id") or "OSV-UNKNOWN")
    summary = _as_str(vuln.get("summary")) or _as_str(vuln.get("details")) or vid
    fixed = _fixed_version(vuln)
    remediation = (
        f"Upgrade {pkg.name} to {fixed} or later."
        if fixed
        else f"Upgrade {pkg.name} to a patched release; see the advisory."
    )
    return Finding(
        rule_id=vid,
        title=f"Known vulnerability in {pkg.name} {pkg.version}",
        severity=_severity(vuln),
        category=RiskCategory.INTEGRITY,
        description=f"{summary[:220]} (affects {pkg.name}=={pkg.version}).",
        remediation=remediation,
        entity_id=pkg.id,
        entity_name=pkg.name,
        source_evidence=[ev.model_copy() for ev in pkg.source_evidence] or [_synthetic_ev(pkg)],
    )


def _severity(vuln: dict[str, Any]) -> Severity:
    for holder in (vuln, *(_iter_dicts(vuln.get("affected")))):
        ds = holder.get("database_specific") if isinstance(holder, dict) else None
        word = ds.get("severity") if isinstance(ds, dict) else None
        if isinstance(word, str) and word.lower() in _SEVERITY_WORD:
            return _SEVERITY_WORD[word.lower()]
    return Severity.MEDIUM


def _fixed_version(vuln: dict[str, Any]) -> str | None:
    for affected in _iter_dicts(vuln.get("affected")):
        for rng in _iter_dicts(affected.get("ranges")):
            for event in _iter_dicts(rng.get("events")):
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed:
                    return fixed
    return None


def _iter_dicts(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _synthetic_ev(pkg: Package) -> Evidence:
    return Evidence(
        file="<manifest>", line_start=1, line_end=1, snippet=pkg.name,
        matched_pattern="osv", confidence=0.9,
    )
