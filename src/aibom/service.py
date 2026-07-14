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
from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.findings import Finding, SecurityScore
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
) -> ScanResult:
    """Statically scan ``target`` and evaluate risk.

    ``resolve`` enables Hugging Face metadata enrichment (network).
    ``vulns`` enables OSV known-vulnerability mapping for pinned AI packages
    (network); it defaults to ``resolve`` so callers with network get both.
    ``display_target`` overrides the target string recorded in the metadata
    (used by the API so reports show the repo URL, not a temp path).
    """
    if vulns is None:
        vulns = resolve
    started = time.monotonic()
    inventory = Inventory(
        metadata=ScanMetadata(
            tool_version=__version__,
            target=display_target or str(Path(target).resolve()),
        )
    )
    RepoCollector(target, disabled_detectors=disabled_detectors).collect(inventory)
    DependencyCollector(target).collect(inventory)

    if resolve or hf_cache is not None:
        client = HFClient(cache_dir=hf_cache, offline=not resolve)
        HuggingFaceResolver(client).resolve(inventory)

    apply_confidence_filter(inventory, min_confidence)

    findings = evaluate_risk(inventory)
    if vulns:
        # Online enrichment: map declared packages to known vulnerabilities (OSV).
        findings = order_findings(findings + OSVMapper().map(inventory))
    score = score_findings(findings)
    inventory.stats.duration_ms = int((time.monotonic() - started) * 1000)
    return ScanResult(inventory=inventory, findings=findings, score=score)


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
