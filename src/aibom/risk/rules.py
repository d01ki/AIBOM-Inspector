"""Deterministic risk rules (SPEC §6, TDR-001…010).

Each rule is a pure function ``Inventory -> list[Finding]``. Rules never execute
or load anything; they reason only over the inventory's entities, signals, and
evidence. Findings carry the evidence of whatever they fired on, preserving the
"no evidence, no claim" contract.
"""

from __future__ import annotations

from collections.abc import Callable

from aibom.inventory import Inventory
from aibom.models.entities import Dataset, EntityType, Model
from aibom.models.evidence import Evidence
from aibom.models.findings import Finding, RiskCategory, Severity
from aibom.spdx import is_known_license, is_spdx

Rule = Callable[[Inventory], list[Finding]]

# Pickle-based serialization formats — arbitrary code execution on load.
_PICKLE_FORMATS = {"pickle", "pkl", "bin", "pt", "pth", "ckpt"}

# Popular model families and the orgs that legitimately publish them. A model
# whose name mentions a family but comes from an org outside this set is a
# possible typosquat / impersonation.
_FAMILY_LEGIT_ORGS: dict[str, set[str]] = {
    "llama": {"meta-llama", "meta", "huggyllama"},
    "mistral": {"mistralai"},
    "mixtral": {"mistralai"},
    "gemma": {"google"},
    "qwen": {"qwen"},
    "falcon": {"tiiuae"},
    "deepseek": {"deepseek-ai"},
    "phi": {"microsoft"},
    "stable-diffusion": {"stabilityai", "runwayml", "compvis", "stability-ai"},
}

# Curated set of officially deprecated / superseded model ids.
_DEPRECATED_MODELS = {
    "text-davinci-003", "text-davinci-002", "code-davinci-002",
    "gpt-3.5-turbo-0301", "gpt-4-0314", "text-ada-001", "text-babbage-001",
    "text-curie-001",
}


def _copy_evidence(evidence: list[Evidence]) -> list[Evidence]:
    return [ev.model_copy() for ev in evidence]


def _models(inv: Inventory) -> list[Model]:
    return [e for e in inv.by_type(EntityType.MODEL) if isinstance(e, Model)]


def _datasets(inv: Inventory) -> list[Dataset]:
    return [e for e in inv.by_type(EntityType.DATASET) if isinstance(e, Dataset)]


# ── TDR-001 — pickle/.bin weights ────────────────────────────────────────────


def tdr_001_pickle_weights(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        pickled = sorted({f.lower() for f in m.formats} & _PICKLE_FORMATS)
        if not pickled:
            continue
        out.append(
            Finding(
                rule_id="TDR-001",
                title="Model uses a pickle-based weight format",
                severity=Severity.HIGH,
                category=RiskCategory.INTEGRITY,
                description=(
                    f"'{m.name}' ships weights as {', '.join(pickled)}. Pickle-based "
                    "formats execute arbitrary code when loaded."
                ),
                remediation="Prefer safetensors; scan the file with picklescan/modelscan first.",
                entity_id=m.id,
                entity_name=m.name,
                source_evidence=_copy_evidence(m.source_evidence),
            )
        )
    return out


# ── TDR-002 — unpinned revision ──────────────────────────────────────────────


def tdr_002_unpinned_revision(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        if m.provider != "huggingface" or m.revision_pinned:
            continue
        out.append(
            Finding(
                rule_id="TDR-002",
                title="Model reference is not pinned to a revision",
                severity=Severity.MEDIUM,
                category=RiskCategory.INTEGRITY,
                description=(
                    f"'{m.name}' is referenced without a pinned revision/commit; the "
                    "resolved weights can change silently upstream."
                ),
                remediation="Pin `revision=<commit-sha>` in the model load call.",
                entity_id=m.id,
                entity_name=m.name,
                source_evidence=_copy_evidence(m.source_evidence),
            )
        )
    return out


# ── TDR-003 — typosquat / family impersonation ───────────────────────────────


def tdr_003_typosquat(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        if m.provider != "huggingface" or "/" not in m.name:
            continue
        org, _, name = m.name.partition("/")
        org_l, name_l = org.lower(), name.lower()
        for family, legit in _FAMILY_LEGIT_ORGS.items():
            if family in name_l and org_l not in legit:
                out.append(
                    Finding(
                        rule_id="TDR-003",
                        title="Model name impersonates a popular family",
                        severity=Severity.HIGH,
                        category=RiskCategory.PROVENANCE,
                        description=(
                            f"'{m.name}' mentions the '{family}' family but is published by "
                            f"'{org}', which is not a recognized publisher of it — possible "
                            "typosquat / impersonation."
                        ),
                        remediation=(
                            f"Confirm the intended source (official orgs: "
                            f"{', '.join(sorted(legit))}) before trusting these weights."
                        ),
                        entity_id=m.id,
                        entity_name=m.name,
                        source_evidence=_copy_evidence(m.source_evidence),
                    )
                )
                break
    return out


# ── TDR-004 — missing model card (needs resolution) ──────────────────────────


def tdr_004_missing_model_card(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        if not m.resolved or m.has_model_card is not False:
            continue
        out.append(
            Finding(
                rule_id="TDR-004",
                title="Model has no model card",
                severity=Severity.LOW,
                category=RiskCategory.PROVENANCE,
                description=f"'{m.name}' has no model card on the hub — intended use and "
                "limitations are undocumented.",
                remediation="Prefer models with a documented card; document usage internally.",
                entity_id=m.id,
                entity_name=m.name,
                source_evidence=_copy_evidence(m.source_evidence),
            )
        )
    return out


# ── TDR-005 — license issues (needs resolution) ──────────────────────────────


def tdr_005_license(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        if not m.resolved:
            continue
        if m.license is None:
            out.append(
                Finding(
                    rule_id="TDR-005",
                    title="Model license is unknown",
                    severity=Severity.MEDIUM,
                    category=RiskCategory.LICENSING,
                    description=f"'{m.name}' declares no license on the hub; redistribution "
                    "and commercial-use terms are unclear.",
                    remediation="Establish the license before shipping; avoid unlicensed weights.",
                    entity_id=m.id,
                    entity_name=m.name,
                    source_evidence=_copy_evidence(m.source_evidence),
                )
            )
        elif not is_spdx(m.license) and not is_known_license(m.license):
            out.append(
                Finding(
                    rule_id="TDR-005",
                    title="Model license is non-SPDX / unrecognized",
                    severity=Severity.LOW,
                    category=RiskCategory.LICENSING,
                    description=f"'{m.name}' uses license '{m.license}', which is not a "
                    "recognized SPDX id — review compatibility manually.",
                    remediation="Map the license to an SPDX id and check repo compatibility.",
                    entity_id=m.id,
                    entity_name=m.name,
                    source_evidence=_copy_evidence(m.source_evidence),
                )
            )
    return out


# ── TDR-006 — unverified author / low downloads (needs resolution) ───────────


def tdr_006_unverified_author(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        if not m.resolved or m.downloads is None or m.downloads >= 50:
            continue
        out.append(
            Finding(
                rule_id="TDR-006",
                title="Model has very low adoption",
                severity=Severity.MEDIUM,
                category=RiskCategory.PROVENANCE,
                description=(
                    f"'{m.name}' has only {m.downloads} downloads"
                    f"{f' (author: {m.author})' if m.author else ''} — little community "
                    "scrutiny; verify the author is who you expect."
                ),
                remediation="Verify author identity and prefer widely-used, audited models.",
                entity_id=m.id,
                entity_name=m.name,
                source_evidence=_copy_evidence(m.source_evidence),
            )
        )
    return out


# ── TDR-007 — hardcoded secret near AI call ──────────────────────────────────


def tdr_007_hardcoded_secret(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    ai_files = {
        ev.file
        for e in inv.entities
        for ev in e.source_evidence
    }
    for sig in inv.signals_of("hardcoded_secret"):
        ev = sig.source_evidence[0] if sig.source_evidence else None
        near_ai = ev is not None and ev.file in ai_files
        out.append(
            Finding(
                rule_id="TDR-007",
                title="Hardcoded secret near AI usage"
                if near_ai
                else "Hardcoded secret detected",
                severity=Severity.CRITICAL if near_ai else Severity.HIGH,
                category=RiskCategory.CONFIGURATION,
                description=(
                    f"A secret literal was found at {ev.location() if ev else '<unknown>'}"
                    + (" in a file that also uses AI services/models." if near_ai else ".")
                ),
                remediation="Move the secret to an environment variable or secrets manager; "
                "rotate the exposed credential.",
                source_evidence=_copy_evidence(sig.source_evidence),
            )
        )
    return out


# ── TDR-008 — dataset without provenance ─────────────────────────────────────


def tdr_008_dataset_provenance(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for d in _datasets(inv):
        if d.provenance:
            continue
        out.append(
            Finding(
                rule_id="TDR-008",
                title="Dataset has no provenance metadata",
                severity=Severity.LOW,
                category=RiskCategory.PROVENANCE,
                description=f"'{d.name}' is used without provenance metadata; poisoned or "
                "mislabeled data would be hard to detect.",
                remediation="Record the dataset source, version, and integrity hash.",
                entity_id=d.id,
                entity_name=d.name,
                source_evidence=_copy_evidence(d.source_evidence),
            )
        )
    return out


# ── TDR-009 — trust_remote_code=True ─────────────────────────────────────────


def tdr_009_trust_remote_code(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for sig in inv.signals_of("trust_remote_code"):
        ev = sig.source_evidence[0] if sig.source_evidence else None
        out.append(
            Finding(
                rule_id="TDR-009",
                title="trust_remote_code=True enables arbitrary code execution",
                severity=Severity.HIGH,
                category=RiskCategory.CONFIGURATION,
                description=(
                    f"`trust_remote_code=True` at {ev.location() if ev else '<unknown>'} lets "
                    "the model repository run arbitrary code at load time."
                ),
                remediation="Remove trust_remote_code, or pin a reviewed revision and vet the "
                "repo's custom code first.",
                source_evidence=_copy_evidence(sig.source_evidence),
            )
        )
    return out


# ── TDR-010 — deprecated / yanked model ──────────────────────────────────────


def tdr_010_deprecated_model(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for m in _models(inv):
        if m.name.lower() not in _DEPRECATED_MODELS:
            continue
        out.append(
            Finding(
                rule_id="TDR-010",
                title="Deprecated model referenced",
                severity=Severity.MEDIUM,
                category=RiskCategory.PROVENANCE,
                description=f"'{m.name}' is a deprecated/superseded model and may be removed "
                "or unmaintained.",
                remediation="Migrate to a currently-supported model.",
                entity_id=m.id,
                entity_name=m.name,
                source_evidence=_copy_evidence(m.source_evidence),
            )
        )
    return out


#: Registry of all rules, evaluated in order.
ALL_RULES: list[Rule] = [
    tdr_001_pickle_weights,
    tdr_002_unpinned_revision,
    tdr_003_typosquat,
    tdr_004_missing_model_card,
    tdr_005_license,
    tdr_006_unverified_author,
    tdr_007_hardcoded_secret,
    tdr_008_dataset_provenance,
    tdr_009_trust_remote_code,
    tdr_010_deprecated_model,
]
