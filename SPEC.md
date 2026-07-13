# — AI Supply Chain Discovery & Risk Platform

> Working name. "" = Japanese for "to trace / follow a path back to its origin."

**Version:** 0.2 (revised specification) · **Date:** 2026-07-13 · **License:** Apache-2.0 (planned)

---

## 1. Vision

Open-source platform that **discovers, inventories, analyzes and visualizes AI supply chains**. Beyond generating an AIBOM,  helps defenders understand attack surface, provenance, and governance risk — the "Dependency-Track for AI."

### Differentiation (vs. prior art)

| Tool | Gap  fills |
|---|---|
| OWASP AIBOM Generator | Generates AIBOM for a single HF model.  *discovers* AI usage across a codebase, resolves it, and adds graph + risk analysis. |
| Trivy / Syft (SBOM) | Package-level only; blind to models, datasets, prompts, agents. |
| Dependency-Track | Consumes SBOMs; no AI-specific discovery or risk rules. |

## 2. Scope

### 2.1 MVP (v0.x — Arsenal demo target)

**One pipeline, done well:** GitHub/local repository scan + Hugging Face resolution → extended AIBOM → interactive graph + evidence-backed risk findings.

1. **Repository scanning (static only):** detect model references (`from_pretrained`, HF URLs, GGUF/safetensors/pickle files, `transformers`/`langchain`/`openai` usage), prompts (template files, hardcoded system prompts), datasets (`load_dataset`, data file references).
2. **Hugging Face resolution:** for each detected model/dataset — metadata, license, model card, file formats, revision pinning status, download stats, author.
3. **Extended AIBOM generation:** CycloneDX 1.6 JSON (ML-BOM component types) as the base format; -specific fields via CycloneDX `properties` namespace `:*`. Never a proprietary-only format.
4. **Dependency graph:** entities + relationships, exported as JSON; interactive view in dashboard.
5. **Risk findings:** rule-based checks (§6) with severity + evidence + remediation.
6. **Outputs:** CLI → JSON / CycloneDX / self-contained HTML report; FastAPI + React dashboard on top.

### 2.2 Post-MVP (plugin collectors)

Ollama, Docker images, MCP server configs, LangChain/LangGraph graphs, OpenAI/Anthropic API usage mapping, attack-path simulation, RAG dependency mapping, policy engine (OPA-style), continuous monitoring, SPDX 3.0 AI Profile export.

### 2.3 Non-goals

- No runtime protection / guardrails (inventory & analysis only).
- No model vulnerability testing (jailbreak, adversarial robustness).
- **Never executes scanned code or loads scanned models.** Static analysis only.
- No SaaS; local-first, air-gap friendly, zero telemetry.

## 3. Architecture

```
CLI ( scan / report / serve)
        │
Collectors (plugin interface)          MVP: repo, huggingface
        ▼
Normalizer  → unified schema (§4), Pydantic models
        ▼
Inventory Store (SQLite; content-addressed snapshots)
        ├─ AIBOM Engine   → CycloneDX 1.6 + :* properties
        ├─ Graph Engine   → NetworkX; JSON export
        └─ Risk Engine    → YAML rules + evidence; LLM explain (opt-in)
        ▼
Outputs: JSON · CycloneDX · HTML report · FastAPI API · React dashboard
```

Principles: CLI-first (CI-friendly, exit codes by severity), dashboard is a layer not the core; every collector a plugin behind one interface; SQLite not a graph DB (MVP graphs are small); works fully offline against a cached HF metadata snapshot.

## 4. Data Model (unified schema)

Core entities (all Pydantic, all with `source_evidence: list[Evidence]`):

| Entity | Key fields |
|---|---|
| `Model` | name, provider, revision (pinned?), formats, license, model_card, author |
| `Dataset` | name, source, license, provenance |
| `Prompt` | location, kind (system/template), hash |
| `Agent` | framework, tools bound, model refs |
| `Tool` / `Service` | MCP server, external API, endpoint |
| `License` | SPDX id, compatibility class |

Relationships (typed edges): `depends_on`, `fine_tuned_from`, `trained_on`, `served_by`, `invokes`, `uses_prompt`, `licensed_under`.

`Evidence` = file path + line span + matched pattern + confidence. **Every entity and finding must carry evidence** — this is the trust contract of the tool.

## 5. Threat Model — what  detects

Assets: models, datasets, prompts, agent tool bindings. Adversary: upstream supply-chain attacker (malicious/typosquatted model, poisoned dataset, hijacked account, malicious MCP server), plus negligent-insider risks (unpinned deps, license violations).

## 6. Risk Rules (MVP set)

Rule-based, deterministic, YAML-defined. Each finding: `rule_id`, severity (info/low/med/high/critical), evidence, remediation.

| ID | Check | Sev (default) |
|---|---|---|
| TDR-001 | Model distributed as pickle/`.bin` (arbitrary code exec on load) vs safetensors | High |
| TDR-002 | Model reference without pinned revision/commit | Medium |
| TDR-003 | Name similar to popular model (typosquat heuristic: edit distance + download gap) | High |
| TDR-004 | Missing or empty model card | Low |
| TDR-005 | License missing, non-SPDX, or incompatible with repo license | Medium |
| TDR-006 | Model/dataset from unverified author w/ low downloads & recent creation | Medium |
| TDR-007 | Hardcoded API keys/secrets near AI calls | Critical |
| TDR-008 | Dataset with no provenance metadata | Low |
| TDR-009 | `trust_remote_code=True` usage | High |
| TDR-010 | Deprecated/yanked model referenced | Medium |

**Security score** = weighted aggregate (0–100) over categories {integrity, provenance, licensing, configuration}, formula documented in the report itself. **LLM assistance is opt-in and limited to natural-language explanation of deterministic findings** — never the source of a score (reproducibility requirement).

## 7. Engineering Rules

Python 3.12+, FastAPI, React+TypeScript, Pydantic v2 everywhere, strict typing (mypy --strict), `uv` for env, ruff for lint. Single responsibility, dependency injection, structured logging (JSON), OpenAPI docs, conventional commits, no hardcoded secrets. Every module independently executable; collectors/rules are plugins (entry points).

**Testing:** pytest; each rule tested against a **golden fixture repo** (`tests/fixtures/vulnerable-ai-app/`) with known-good expected findings; target ≥85% coverage on engines; CLI e2e test producing a full CycloneDX doc validated against the official schema.

## 8. Black Hat Arsenal Demo Plan

1. Live scan of a deliberately vulnerable demo repo (ships with the tool).
2. Graph appears: app → agents → models → datasets → external services.
3. Click a red node → evidence-backed finding (e.g., pickle model, typosquat).
4. Export CycloneDX → import into Dependency-Track to show ecosystem fit.
5. Takeaway: production-quality OSS, `pip install `.

## 9. Success Metrics

- Scan of a 50k-LOC repo < 60 s (without network), < 5 min with HF resolution.
- Zero false-negative on golden fixture; false-positive rate tracked per rule.
- Valid CycloneDX 1.6 (schema-validated) accepted by Dependency-Track.
- One command from clone to demo: ` scan ./repo --serve`.

## 10. Milestones

| M | Deliverable | Status |
|---|---|---|
| M1 | Schema + repo collector + evidence engine | ✅ done |
| M2 | HF resolver + AIBOM (CycloneDX) export | ✅ done |
| M3 | Risk rules TDR-001..010 + scoring + HTML report | ✅ done |
| M4 | FastAPI backend + web UI (repo URL → AIBOM + score) | ✅ done · graph viz pending |
| M5 | Demo fixture repo, docs, packaging (PyPI), Arsenal submission | planned |
