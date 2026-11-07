"""OSV.dev client + mapper.

Queries the public OSV API for each pinned package and turns matching
advisories into :class:`~aibom.models.findings.Finding` objects. Constraints,
mirroring the resolvers:

* **Network-optional.** A transport error never fails the scan, but it is
  recorded as a failed lookup (``ScanStats.vuln_lookup``), never as "no
  vulnerabilities".
* **Precise.** Only exact (``==``) pinned versions are queried, so a finding
  means "this exact version is affected" — no range-guessing false positives.
* **One finding per vulnerability.** OSV returns the same issue once per
  database (GHSA, PYSEC, ...). Records linked by id or alias are merged into
  one finding that lists every id and each database's severity.
* **Release versions only.** A fix version comes from the package's
  ``ECOSYSTEM``/``SEMVER`` ranges; a ``GIT`` range's commit hash is never
  presented as a version to upgrade to.
* **Injectable.** ``OSVMapper`` takes a client, so tests use a fake.
"""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from typing import Any, Protocol

from aibom.inventory import Inventory, VulnLookup
from aibom.models.entities import EntityType, Package
from aibom.models.evidence import Evidence
from aibom.models.findings import (
    Advisory,
    Finding,
    RiskCategory,
    Severity,
    SeveritySource,
)

_OSV_URL = "https://api.osv.dev/v1/query"
_OSV_VULN_PAGE = "https://osv.dev/vulnerability/"
_TIMEOUT = 10.0

_SEVERITY_WORD = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
#: Range types whose events are package release versions.
_RELEASE_RANGES = {"ECOSYSTEM", "SEMVER"}
#: Preferred primary id when several databases describe one vulnerability.
_ID_PREFERENCE = ("GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "OSV-", "CVE-")


class VulnLookupError(RuntimeError):
    """The advisory database could not be queried (network, timeout, bad reply)."""


class VulnClient(Protocol):
    def query(self, name: str, ecosystem: str, version: str) -> list[dict[str, Any]]: ...


class OSVClient:
    """Read-only OSV.dev client. Returns the ``vulns`` list.

    Raises :class:`VulnLookupError` when the query fails, so the caller can
    tell "no advisories" apart from "could not ask".
    """

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
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            raise VulnLookupError(f"OSV query for {name} failed: {exc}") from exc
        if not isinstance(data, dict):
            raise VulnLookupError(f"OSV query for {name} returned an unexpected reply")
        vulns = data.get("vulns")
        return vulns if isinstance(vulns, list) else []


class OSVMapper:
    """Map pinned packages in an inventory to OSV vulnerability findings.

    Every pinned dependency is checked (the BOM is complete), AI packages
    first; ``max_queries`` bounds the total network calls on huge lockfiles.
    After :meth:`map`, :attr:`coverage` says what was and was not looked up.
    """

    def __init__(self, client: VulnClient | None = None, *, max_queries: int = 100) -> None:
        self.client = client or OSVClient()
        self.max_queries = max_queries
        self.coverage = VulnLookup()

    def map(self, inventory: Inventory) -> list[Finding]:
        packages = [
            pkg for pkg in inventory.by_type(EntityType.PACKAGE)
            if isinstance(pkg, Package) and pkg.ecosystem
        ]
        candidates = [p for p in packages if p.version_pinned and p.version]
        candidates.sort(key=lambda p: (not p.ai, p.name.lower()))
        queried = candidates[: self.max_queries]
        coverage = VulnLookup(
            requested=True,
            queried=0,
            not_queried_unpinned=len(packages) - len(candidates),
            not_queried_over_limit=len(candidates) - len(queried),
        )
        findings: list[Finding] = []
        for pkg in queried:
            try:
                vulns = self.client.query(pkg.name, pkg.ecosystem or "", pkg.version or "")
            except VulnLookupError as exc:
                coverage.failed += 1
                coverage.errors.append(str(exc)[:200])
                continue
            coverage.queried += 1
            live = [v for v in vulns if isinstance(v, dict) and not v.get("withdrawn")]
            findings.extend(_to_finding(pkg, group) for group in _merge_aliases(live))
        coverage.status = (
            "failed" if queried and coverage.failed == len(queried)
            else "partial" if coverage.failed or coverage.not_queried_over_limit
            else "complete"
        )
        self.coverage = coverage
        return findings


def _merge_aliases(vulns: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group advisory records that share an id or alias (union-find)."""
    parent = list(range(len(vulns)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for index, vuln in enumerate(vulns):
        for name in _names(vuln):
            if name in owner:
                parent[find(index)] = find(owner[name])
            else:
                owner[name] = index
    groups: dict[int, list[dict[str, Any]]] = {}
    for index, vuln in enumerate(vulns):
        groups.setdefault(find(index), []).append(vuln)
    return list(groups.values())


def _names(vuln: dict[str, Any]) -> list[str]:
    ids = [vuln.get("id"), *(vuln.get("aliases") or [])]
    return [i.strip().upper() for i in ids if isinstance(i, str) and i.strip()]


def _primary(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    def rank(vuln: dict[str, Any]) -> tuple[int, str]:
        vid = str(vuln.get("id") or "")
        for position, prefix in enumerate(_ID_PREFERENCE):
            if vid.upper().startswith(prefix):
                return (position, vid)
        return (len(_ID_PREFERENCE), vid)

    return min(vulns, key=rank)


def _to_finding(pkg: Package, vulns: list[dict[str, Any]]) -> Finding:
    primary = _primary(vulns)
    vid = str(primary.get("id") or "OSV-UNKNOWN")
    record_ids = sorted({str(v.get("id")) for v in vulns if v.get("id")})
    aliases = sorted({n for v in vulns for n in _names(v)} - {i.upper() for i in record_ids})
    summary = (
        next((s for v in [primary, *vulns] if (s := _as_str(v.get("summary")))), None)
        or _as_str(primary.get("details")) or vid
    )
    installed = pkg.version or ""
    fixed = recommended_upgrade(
        [_lowest_above(_fixed_versions(v, pkg), installed) for v in vulns]
    )
    sources = [s for v in vulns for s in _severity_sources(v)]
    rated = [s.severity for s in sources if s.severity is not None]
    severity = max(rated, key=lambda s: s.rank) if rated else Severity.MEDIUM
    rule = (
        "highest rating among the merged advisories" if rated
        else "no advisory rates it; shown as medium until rated"
    )
    count = len(record_ids)
    if fixed:
        remediation = f"Upgrade {pkg.name} to {fixed} or later" + (
            f" (fixes all {count} merged advisories)." if count > 1 else "."
        )
    else:
        remediation = (
            f"No fixed {pkg.ecosystem} release is recorded for {pkg.name}; "
            f"see {_OSV_VULN_PAGE}{vid}."
        )
    modified = max((m for v in vulns if (m := _as_str(v.get("modified")))), default=None)
    advisory = Advisory(
        ids=[*record_ids, *aliases],
        urls=[_OSV_VULN_PAGE + i for i in record_ids],
        installed_version=installed,
        fixed_version=fixed,
        affected_ranges=sorted({r for v in vulns for r in _range_texts(v, pkg)}),
        severity_rule=rule,
        severity_sources=sources,
        modified=modified,
    )
    also = f" Also published as {', '.join(i for i in advisory.ids if i != vid)}." if (
        len(advisory.ids) > 1
    ) else ""
    return Finding(
        rule_id=vid,
        title=f"Known vulnerability in {pkg.name} {installed}",
        severity=severity,
        category=RiskCategory.INTEGRITY,
        description=f"{summary[:220]} (affects {pkg.name}=={installed}).{also}",
        remediation=remediation,
        entity_id=pkg.id,
        entity_name=pkg.name,
        source_evidence=[ev.model_copy() for ev in pkg.source_evidence] or [_synthetic_ev(pkg)],
        advisory=advisory,
    )


def _affected_for(vuln: dict[str, Any], pkg: Package) -> list[dict[str, Any]]:
    """The ``affected`` entries describing this package (all of them if unnamed)."""
    entries = _iter_dicts(vuln.get("affected"))
    want = _norm_name(pkg.name, pkg.ecosystem)
    named = [
        a for a in entries
        if isinstance(a.get("package"), dict) and a["package"].get("name")
    ]
    if not named:
        return entries
    return [
        a for a in named
        if _norm_name(str(a["package"]["name"]), str(a["package"].get("ecosystem") or ""))
        == want
    ]


def _fixed_versions(vuln: dict[str, Any], pkg: Package) -> list[str]:
    out: list[str] = []
    for affected in _affected_for(vuln, pkg):
        for rng in _iter_dicts(affected.get("ranges")):
            if str(rng.get("type") or "").upper() not in _RELEASE_RANGES:
                continue  # GIT ranges name commits, not releases
            for event in _iter_dicts(rng.get("events")):
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed and not _looks_like_commit(fixed):
                    out.append(fixed)
    return out


def _range_texts(vuln: dict[str, Any], pkg: Package) -> list[str]:
    texts: list[str] = []
    for affected in _affected_for(vuln, pkg):
        for rng in _iter_dicts(affected.get("ranges")):
            if str(rng.get("type") or "").upper() not in _RELEASE_RANGES:
                continue
            low: str | None = None
            for event in _iter_dicts(rng.get("events")):
                if isinstance(event.get("introduced"), str):
                    low = event["introduced"]
                elif isinstance(event.get("fixed"), str) and low is not None:
                    texts.append(f">={low}, <{event['fixed']}" if low != "0" else
                                 f"<{event['fixed']}")
                    low = None
                elif isinstance(event.get("last_affected"), str) and low is not None:
                    texts.append(f">={low}, <={event['last_affected']}")
                    low = None
            if low is not None:
                texts.append(f">={low}" if low != "0" else "all versions")
    return texts


def _severity_sources(vuln: dict[str, Any]) -> list[SeveritySource]:
    vid = str(vuln.get("id") or "OSV-UNKNOWN")
    sources: list[SeveritySource] = []
    for holder in (vuln, *_iter_dicts(vuln.get("affected"))):
        ds = holder.get("database_specific")
        word = ds.get("severity") if isinstance(ds, dict) else None
        if isinstance(word, str) and word.lower() in _SEVERITY_WORD:
            sources.append(SeveritySource(
                advisory_id=vid, severity=_SEVERITY_WORD[word.lower()],
                source="database_specific.severity",
            ))
            break
    for entry in _iter_dicts(vuln.get("severity")):
        kind = str(entry.get("type") or "")
        vector = _as_str(entry.get("score"))
        if not vector:
            continue
        score = cvss3_base_score(vector) if kind == "CVSS_V3" else None
        sources.append(SeveritySource(
            advisory_id=vid, source=kind or "severity", vector=vector, score=score,
            severity=_cvss_severity(score) if score is not None else None,
        ))
    if not sources:
        sources.append(SeveritySource(advisory_id=vid, source="none"))
    return sources


# --- versions ----------------------------------------------------------------

_COMMIT = re.compile(r"^[0-9a-f]{12,64}$", re.I)
_RELEASE = re.compile(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(.*)$", re.I)
_PHASE = (("dev", -4), ("a", -3), ("alpha", -3), ("b", -2), ("beta", -2),
          ("c", -1), ("rc", -1), ("pre", -1), ("post", 1))


def _looks_like_commit(value: str) -> bool:
    return bool(_COMMIT.match(value)) and "." not in value


def _version_key(value: str) -> tuple[Any, ...] | None:
    """A sortable key for PEP 440 / semver style release strings, or None."""
    match = _RELEASE.match(value.strip())
    if not match or _looks_like_commit(value):
        return None
    epoch = int(match.group(1) or 0)
    release = [int(p) for p in match.group(2).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = match.group(3).lower().lstrip(".-_+")
    phase, number = 0, 0
    if rest:
        word = re.match(r"([a-z]+)\.?(\d*)", rest)
        if not word:
            return None
        phase = dict(_PHASE).get(word.group(1), -5)
        number = int(word.group(2) or 0)
    return (epoch, tuple(release), phase, number)


def _lowest_above(candidates: list[str], installed: str) -> str | None:
    """The lowest candidate release above ``installed`` (the minimum safe upgrade).

    With several release lines (``<2.3.1`` and ``>=3.0, <3.0.3``) the lowest
    fix above the installed version is the one on the installed line.
    """
    base = _version_key(installed)
    keyed = [(k, c) for c in set(candidates) if (k := _version_key(c)) is not None]
    above = [(k, c) for k, c in keyed if base is None or k > base]
    return min(above)[1] if above else None


def recommended_upgrade(per_advisory: list[str | None]) -> str | None:
    """One version that clears every advisory with a known fix: the highest
    of their minimal fixes. Advisories without a known fix are ignored here
    and must be reported separately."""
    keyed = [(k, v) for v in per_advisory if v and (k := _version_key(v)) is not None]
    return max(keyed)[1] if keyed else None


def group_by_package(findings: list[Finding]) -> list[dict[str, Any]]:
    """Known-vulnerability findings grouped per package with one upgrade target.

    ``recommended_version`` is the lowest version that clears every advisory
    with a known fix; advisories without a known fix are counted separately,
    so the recommendation never claims more than it covers.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if f.advisory is not None and f.entity_id:
            groups.setdefault(f.entity_id, []).append(f)
    out: list[dict[str, Any]] = []
    for entity_id, items in groups.items():
        fixes = [f.advisory.fixed_version for f in items if f.advisory]
        worst = max(items, key=lambda f: f.severity.rank).severity
        out.append({
            "entity_id": entity_id,
            "package": items[0].entity_name,
            "installed_version": items[0].advisory.installed_version if items[0].advisory else None,
            "severity": worst.value,
            "advisories": [f.rule_id for f in items],
            "recommended_version": recommended_upgrade(fixes),
            "without_known_fix": sum(1 for v in fixes if not v),
        })
    out.sort(key=lambda g: (-Severity(g["severity"]).rank, str(g["package"]).lower()))
    return out


def _norm_name(name: str, ecosystem: str | None) -> str:
    eco = (ecosystem or "").lower()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name.strip().lower())
    return name.strip().lower()


# --- CVSS v3 -------------------------------------------------------------------

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string, or None if malformed."""
    if not vector.upper().startswith("CVSS:3"):
        return None
    metrics = dict(
        part.split(":", 1) for part in vector.split("/")[1:] if ":" in part
    )
    try:
        scope = metrics["S"]
        values = {k: _CVSS3[k][metrics[k]] for k in _CVSS3}
        pr = _PR[scope][metrics["PR"]]
    except KeyError:
        return None
    iss = 1 - (1 - values["C"]) * (1 - values["I"]) * (1 - values["A"])
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * values["AV"] * values["AC"] * pr * values["UI"]
    if impact <= 0:
        return 0.0
    raw = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def _cvss_severity(score: float) -> Severity | None:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
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
