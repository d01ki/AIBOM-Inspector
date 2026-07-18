# AIBOM Inspector — Design Specification

**Version:** 0.3 · **License:** Apache-2.0

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
resolution → extended AIBOM → interactive graph + evidence-backed risk findings.

1. **Repository scanning (static only):** detect model references
   (`from_pretrained`, HF URLs, GGUF/safetensors/pickle files,
   `transformers`/`langchain`/`openai` usage), prompts (template files,
   hardcoded system prompts), datasets (`load_dataset`, data file references).
2. **Hugging Face resolution:** for each detected model/dataset — metadata,
   license, model card, file formats, revision pinning status, download stats,
   author.
3. **Extended AIBOM generation:** CycloneDX 1.6 JSON (ML-BOM component types)
   as the base format; tool-specific fields via the CycloneDX `properties`
   namespace `aibom:*`. Never a proprietary-only format.
4. **Dependency graph:** entities + relationships, exported as JSON;
   interactive view in the web UI.
5. **Risk findings:** rule-based checks (§6) with severity + evidence +
   remediation.
6. **Outputs:** CLI → JSON / CycloneDX / SARIF / self-contained HTML report;
   FastAPI + web UI on top.

### 2.2 Non-goals

- No runtime protection / guardrails (inventory & analysis only).
- No model vulnerability testing (jailbreak, adversarial robustness).
- **Never executes scanned code or loads scanned models.** Static analysis only.
- No SaaS; local-first, air-gap friendly, zero telemetry.

## 3. Architecture

```
CLI (aibom scan / serve)
        │
Collectors (plugin interface)          repo, dependencies, huggingface
        ▼
Normalizer → unified schema (§4), Pydantic models
        ▼
Inventory (deduplicating store + typed relationship graph)
        ├─ AIBOM Engine   → CycloneDX 1.6 + aibom:* properties
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
| `Prompt` | location, kind (system/template), hash |
| `Agent` | framework, tools bound, model refs |
| `Service` | MCP server, external API, endpoint |
| `Package` | ecosystem, version, purl, AI flag |

Relationships (typed edges): `depends_on`, `fine_tuned_from`, `trained_on`,
`served_by`, `invokes`, `uses_prompt`, `licensed_under`.

`Evidence` = file path + line span + matched pattern + confidence. **Every
entity and finding must carry evidence** — this is the trust contract of the
tool.

## 5. Threat Model

Assets: models, datasets, prompts, agent tool bindings. Adversary: upstream
supply-chain attacker (malicious/typosquatted model, poisoned dataset, hijacked
account, malicious MCP server), plus negligent-insider risks (unpinned deps,
license violations).

## 6. Risk Rules

Rule-based and deterministic. Each finding: `rule_id`, severity
(info/low/medium/high/critical), evidence, remediation. The authoritative rule
table (TDR-001…012, AIBOM-PROMPT-004, OSV-*) is in
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
`disable_detectors`, `ignore_rules`. CLI flags always override config. This is
how an organization pins one policy across many repositories.

## 9. Success Metrics

- Scan of a 50k-LOC repo < 60 s (without network), < 5 min with HF resolution.
- Zero false-negatives on the golden fixture; precision/recall tracked by the
  reproducible benchmark harness (`benchmark/`).
- Valid CycloneDX 1.6 (schema-validated) accepted by Dependency-Track.
- Valid SARIF 2.1.0 accepted by GitHub Code Scanning.

## 10. Roadmap

- Syntax-aware JavaScript/TypeScript detection (current JS/TS detectors are
  textual).
- Cross-file value resolution (YAML/JSON/TOML config linking).
- MCP capability analysis (tool surface enumeration).
- Plugin collectors: Ollama, Docker images, LangChain/LangGraph graphs,
  attack-path simulation, RAG dependency mapping, policy engine (OPA-style),
  SPDX 3.0 AI Profile export.
- Continuous monitoring mode.
