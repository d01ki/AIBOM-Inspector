"""Scan service — the one pipeline shared by the CLI and the HTTP API.

``run_scan`` turns a local path into a full result: the inventory, the
deterministic findings, and the security score. Keeping this in one place means
the CLI and the FastAPI backend cannot drift apart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from aibom import __version__
from aibom.collectors.dependencies import DependencyCollector
from aibom.collectors.lockfiles import LockfileCollector
from aibom.collectors.repo import RepoCollector
from aibom.config import ignored
from aibom.inventory import Inventory, ScanMetadata
from aibom.linking import link_components
from aibom.models.findings import Finding, SecurityScore
from aibom.policy import production_view
from aibom.provenance import read_commit, source_url_template
from aibom.resolvers.huggingface import HFClient, HuggingFaceResolver
from aibom.risk.engine import evaluate as evaluate_risk
from aibom.risk.engine import order_findings
from aibom.risk.scoring import score_findings
from aibom.vuln.osv import OSVMapper


@dataclass
class ScanResult:
    """Everything a single scan produces."""

    inventory: Inventory
    findings: list[Finding]
    score: SecurityScore


def run_scan(
    target: str | Path,
    *,
    resolve: bool = False,
    vulns: bool | None = None,
    hf_cache: str | Path | None = None,
    min_confidence: float = 0.0,
    display_target: str | None = None,
    disabled_detectors: set[str] | None = None,
    ignore_rules: list[str] | None = None,
    lockfiles: bool = True,
    ref: str | None = None,
) -> ScanResult:
    """Statically scan ``target`` and evaluate risk.

    ``resolve`` enables Hugging Face metadata enrichment (network).
    ``vulns`` enables OSV known-vulnerability mapping for pinned AI packages
    (network); it defaults to ``resolve`` so callers with network get both.
    ``display_target`` overrides the target string recorded in the metadata
    (used by the API so reports show the repo URL, not a temp path).
    ``ignore_rules`` suppresses findings by rule ID (exact, or ``PREFIX-*``);
    suppressed findings are excluded from the score as well. The caller decides
    the policy — this function never reads config from the scanned repo, so a
    scanned third-party repository cannot silence its own findings.
    ``lockfiles`` resolves lockfiles for transitive components and artifact
    digests; turn it off for a manifest-only (top-level) inventory.
    """
    if vulns is None:
        vulns = resolve
    started = time.monotonic()
    commit = read_commit(target)
    inventory = Inventory(
        metadata=ScanMetadata(
            tool_version=__version__,
            target=display_target or str(Path(target).resolve()),
            ref=ref,
            commit=commit,
            source_url_template=(
                source_url_template(display_target, commit) if display_target else None
            ),
        )
    )
    RepoCollector(target, disabled_detectors=disabled_detectors).collect(inventory)
    DependencyCollector(target).collect(inventory)
    if lockfiles:
        # After the manifests: a lockfile resolves what a manifest constrains,
        # adding transitive components, exact versions and artifact digests
        # (CISA 2026 coverage + Component Hash).
        LockfileCollector(target).collect(inventory)
    # Last collector step: every component and package is known, so the
    # linker can connect them (only where a scanned line proves the edge).
    link_components(inventory, target)

    if resolve or hf_cache is not None:
        client = HFClient(cache_dir=hf_cache, offline=not resolve)
        HuggingFaceResolver(client).resolve(inventory)

    apply_confidence_filter(inventory, min_confidence)

    risk_inventory = production_view(inventory)
    findings = evaluate_risk(risk_inventory)
    if vulns:
        # Online enrichment: map declared packages to known vulnerabilities (OSV).
        mapper = OSVMapper()
        findings = order_findings(findings + mapper.map(risk_inventory))
        inventory.stats.vuln_lookup = mapper.coverage
    if ignore_rules:
        findings = [f for f in findings if not _suppressed(f, ignore_rules)]
    score = score_findings(findings)
    inventory.stats.duration_ms = int((time.monotonic() - started) * 1000)
    return ScanResult(inventory=inventory, findings=findings, score=score)


def _suppressed(finding: Finding, rules: list[str]) -> bool:
    """A rule ID or any advisory alias may be named to suppress a finding."""
    names = [finding.rule_id, *(finding.advisory.ids if finding.advisory else [])]
    return any(ignored(name, rules) for name in names)


def apply_confidence_filter(inventory: Inventory, threshold: float) -> None:
    """Drop entities whose best evidence is below ``threshold`` (and dangling edges)."""
    if threshold <= 0.0:
        return
    keep = [
        e for e in inventory.entities if any(ev.confidence >= threshold for ev in e.source_evidence)
    ]
    kept_ids = {e.id for e in keep}
    inventory.entities = keep
    inventory.relationships = [
        r for r in inventory.relationships if r.source_id in kept_ids and r.target_id in kept_ids
    ]
