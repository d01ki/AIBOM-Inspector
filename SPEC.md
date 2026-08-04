# AIBOM Inspector — Design Specification

**Version:** 0.4 · **License:** Apache-2.0

This document is the design contract for AIBOM Inspector: scope, architecture,
data model, threat model, risk rules, and engineering rules. Feature status
lives in [README.md](README.md); planned work lives in §10 (Roadmap).

---

## 1. Vision

Open-source platform that **discovers, inventories, analyzes and visualizes AI
supply chains**. Beyond generating an AIBOM, AIBOM Inspector helps defenders
understand attack surface, provenance, and governance risk — the
"Dependency-Track for AI."

## 2. Scope

### 2.1 Core pipeline

**One pipeline, done well:** GitHub/local repository scan + Hugging Face
resolution → behavioral AIBOM → trust-boundary/dependency graph +
evidence-backed risk findings and revision drift.

1. **Repository scanning (static only):** detect model references
   (`from_pretrained`, HF URLs, GGUF/safetensors/pickle files,
   `transformers`/`langchain`/`openai` usage), prompts (template files,
   hardcoded system prompts), datasets (`load_dataset`, data file references).
2. **Hugging Face resolution:** for each detected model/dataset — metadata,
   license, model card, file formats, revision pinning status, download stats,
   author.
3. **Extended AIBOM generation:** CycloneDX 1.6 JSON (ML-BOM component types)
   as the base format; tool-specific fields via the CycloneDX `properties`
   namespace `aibom:*`. Never a proprietary-only format. The document targets
   the **CISA 2026 SBOM minimum elements** (which replaced the 2021 NTIA
   elements and explicitly cover AI software): document authorship and
   generation context, a primary component, per-component producers,
   identifiers, licenses and artifact digests, and an explicit dependency entry
   for every component. Data static analysis cannot know is *declared* as a
   `cisa:known-unknown` with a reason, never left silently blank —
   see [docs/cisa-2026-minimum-elements.md](docs/cisa-2026-minimum-elements.md).
4. **Exposure, impact, and dependency graph:** entities + relationships plus
   confirmed, privacy-preserving untrusted-input paths through prompt sinks,
   models, directly bound tools, and tool-parameter-controlled operations,
   exported as JSON and rendered in the web UI.
5. **Trust-Boundary / Blast-Radius Drift:** compare baseline and candidate
   scans for new privileged prompt exposure, newly connected capability impact,
   prompt content/target changes, usage escalation, component changes, and
   finding changes. Prompt bodies and tool argument values are never serialized.
6. **Risk findings:** rule-based checks (§6) with severity + evidence +
   remediation.
7. **Outputs:** CLI → JSON / CycloneDX / SARIF / drift JSON / minimum-elements
   conformance JSON / self-contained HTML report; FastAPI + web UI on top.

### 2.2 Non-goals

- No runtime protection / guardrails (inventory & analysis only).
- No model vulnerability testing (jailbreak, adversarial robustness).
- **Never executes scanned code or loads scanned models.** Static analysis only.
- No SaaS; local-first, air-gap friendly, zero telemetry.

## 3. Architecture

```
CLI (aibom scan / diff / serve)
        │
Collectors (plugin interface)          repo, dependencies, lockfiles, huggingface
        ▼
Normalizer → unified schema (§4), Pydantic models
        ▼
Inventory (deduplicating store + typed relationship graph)
        ├─ AIBOM Engine   → CycloneDX 1.6 + aibom:* properties
        ├─ Conformance    → CISA 2026 SBOM minimum elements (any CycloneDX doc)
        ├─ Exposure Engine → sanitized source → prompt sink → model paths
        ├─ Impact Engine  → direct tool binding + parameter → operation paths
        ├─ Drift Engine   → exposure/impact + component revision comparison
        ├─ Graph Engine   → JSON export for the interactive UI
        └─ Risk Engine    → deterministic rules + evidence
        ▼
Outputs: JSON · CycloneDX · SARIF · HTML report · FastAPI API · web UI
```

Principles: CLI-first (CI-friendly, exit codes by severity); the dashboard is a
layer, not the core; every collector is a plugin behind one interface; works
fully offline against a cached HF metadata snapshot.

## 4. Data Model (unified schema)

Core entities (all Pydantic, all with `source_evidence: list[Evidence]`):

| Entity | Key fields |
|---|---|
| `Model` | name, provider, revision (pinned?), formats, license, model_card, author |
| `Dataset` | name, source, license, provenance |
| `Prompt` | location, role/kind, hash, source/sink, trust boundary, model/tool refs, flow, bound capabilities |
| `Agent` | framework, tools bound, model refs |
| `Service` | MCP server, external API, endpoint |
| `Package` | ecosystem, version, purl, AI flag, dependency scope (direct/transitive), artifact digest + algorithm, producing registry, license |

Relationships (typed edges): `depends_on`, `fine_tuned_from`, `trained_on`,
`served_by`, `invokes`, `uses_prompt`, `flows_to`, `licensed_under`.

`ExposurePath` is a derived, non-component artifact: stable prompt anchor,
source kind, sink kind, trust boundary, privilege flag, consuming model ids,
reachability, sanitized flow steps, confidence, and source evidence. It exists
only when the bounded analysis proves user-controlled input.

`ImpactPath` is a derived, non-component artifact joining a privileged
`ExposurePath` to an explicit agent tool binding and a proven flow from a tool
parameter into a recognized high-impact operation. It records potential
consequence and claim confidence, not runtime exploit success.

`Evidence` = file path + line span + matched pattern + confidence. **Every
entity and finding must carry evidence** — this is the trust contract of the
tool.

The exported inventory retains all source contexts. The default risk, graph,
exposure, and impact policy view includes production evidence only; test,
fixture, example, and docs entities remain auditable inventory entries but do
not affect their host repository's findings or score.

## 5. Threat Model

Assets: models, datasets, prompts, agent tool bindings. Adversary: upstream
supply-chain attacker (malicious/typosquatted model, poisoned dataset, hijacked
account, malicious MCP server), plus negligent-insider risks (unpinned deps,
license violations).

## 6. Risk Rules

Rule-based and deterministic. Each finding: `rule_id`, severity
(info/low/medium/high/critical), evidence, remediation. The authoritative rule
table (TDR-001–012, AIBOM-PROMPT-004, AIBOM-IMPACT-001, OSV-*) is in
[README.md](README.md#risk-rules--scoring); rule logic lives in
`src/aibom/risk/rules.py`.

**Package vulnerabilities:** the dependency collector extracts AI/ML libraries
(with versions + purls) from `requirements*.txt` / `pyproject.toml` / `Pipfile`
/ `package.json`, and (with `--resolve`) pinned versions are mapped to known
CVE/GHSA advisories via OSV.dev — each match becoming an evidence-backed
finding.

**Security score** = weighted aggregate (0–100) over categories {integrity,
provenance, licensing, configuration}; the formula is documented in the report
itself. **LLM assistance is opt-in and limited to natural-language explanation
of deterministic findings** — never the source of a finding or score
(reproducibility requirement).

**Suppression** is explicit and auditable: rules can be disabled per
organization via config (`ignore_rules`) or CLI (`--ignore-rule`); suppressed
findings are excluded from the score and the `--fail-on` gate.

## 7. Engineering Rules

Python 3.10+, FastAPI, Pydantic v2 everywhere, strict typing (`mypy --strict`),
`uv` for env, `ruff` for lint. Single responsibility, no hardcoded secrets,
conventional commits. Collectors/detectors are plugins behind stable IDs.

**Testing:** pytest; each rule tested against a **golden fixture repo**
(`tests/fixtures/vulnerable-ai-app/`) with known-good expected findings; CLI
e2e test producing a full CycloneDX doc validated against the official schema.

## 8. Configuration

Scan defaults are read from the scan target's `aibom.toml` (or
`[tool.aibom]` in its `pyproject.toml`): `fail_on`, `min_confidence`,
`disable_detectors`, `ignore_rules`, `lockfiles`, and the SBOM authorship keys
`sbom_author`, `sbom_author_email`, `sbom_supplier`, `sbom_lifecycle`. CLI
flags always override config. This is how an organization pins one policy
across many repositories.

## 9. Success Metrics

- Scan of a 50k-LOC repo < 60 s (without network), < 5 min with HF resolution.
- Zero false-negatives on the golden fixture; precision/recall tracked by the
  reproducible benchmark harness (`benchmark/`).
- Valid CycloneDX 1.6 (schema-validated) accepted by Dependency-Track.
- No CISA 2026 minimum element silently missing from a generated AIBOM: every
  gap is an explicit, reasoned known-unknown declaration.
- Valid SARIF 2.1.0 accepted by GitHub Code Scanning.

## 10. Roadmap

- Cross-file value resolution (YAML/JSON/TOML config linking).
- Cross-file JS/TS flow tracing (tools and prompt constants defined in another
  module); current JS/TS analysis is same-file, like Python.
- TypeScript coverage in the external benchmark corpus.
- MCP capability analysis (tool surface enumeration).
- Plugin collectors: Ollama, Docker images, LangChain/LangGraph graphs,
  attack-path simulation, RAG dependency mapping, policy engine (OPA-style),
  SPDX 3.0 AI Profile export.
- Continuous monitoring mode.
