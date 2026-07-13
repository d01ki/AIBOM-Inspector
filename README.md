---
title: AIBOM Inspector
emoji: 🧬
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8000
pinned: false
license: apache-2.0
---

# AIBOM Inspector

> **Discover, inventory, and analyze AI supply chains — the "Dependency-Track for AI."**
> Static, evidence-backed, local-first. **Never executes scanned code or loads scanned models.**

[![CI](https://github.com/d01ki/AIBOM-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/d01ki/AIBOM-Inspector/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

`aibom` scans a repository and produces an **evidence-backed inventory** of the AI
components it depends on — models, datasets, prompts, agents, and external AI
services — as a first step toward a full **AIBOM** (AI Bill of Materials) and
supply-chain risk analysis.

Every entity it reports is pinned to a concrete `file:line` with the pattern that
matched. **No evidence, no claim** — that is the trust contract of the tool.

---

## Why

Existing SBOM tooling (Trivy, Syft) is package-level and blind to models,
datasets, prompts, and agents. AIBOM generators produce a bill of materials for a
*single* known model. **AIBOM Inspector discovers AI usage across a whole codebase**,
resolves it, and adds graph + risk analysis on top.

| Tool | Gap AIBOM Inspector fills |
|---|---|
| OWASP AIBOM Generator | Generates an AIBOM for a single HF model. AIBOM Inspector *discovers* AI usage across a codebase and adds graph + risk analysis. |
| Trivy / Syft (SBOM) | Package-level only; blind to models, datasets, prompts, agents. |
| Dependency-Track | Consumes SBOMs; no AI-specific discovery or risk rules. |
| `modelscan` / `picklescan` | Scan a *given* model file for unsafe pickles. AIBOM Inspector *finds which models a repo uses in the first place*, then flags the pickle risk in context. |

## Status

**Early alpha (v0.1, M1–M4).** Implemented today:

- ✅ **Web app** — a FastAPI backend (`aibom serve`) + a static single-page UI:
  paste a public repo URL, get the AIBOM, findings, and score in the browser
- ✅ **Interactive dependency graph** — app → agents → models / prompts / services,
  nodes colored by risk; click a node for its evidence-backed findings (no JS deps)

- ✅ Unified Pydantic schema with mandatory evidence
- ✅ Static repository collector (models, datasets, prompts, agents, services)
- ✅ Deduplicating inventory + typed relationship graph
- ✅ **Hugging Face resolver** — enriches HF models/datasets with license, model-card
  presence, serialization formats, author, downloads, gated status (network-optional,
  cache-backed, offline-friendly; **never downloads or loads weights**)
- ✅ **CycloneDX 1.6 (ML-BOM) export** — `machine-learning-model` / `data` components,
  services, dependency graph, and AIBOM-specific data in the `aibom:*` property namespace;
  **validated against the official CycloneDX 1.6 JSON schema** in the test suite
- ✅ **Deterministic risk rules (TDR-001…010)** + a reproducible 0–100 security score
  over integrity / provenance / licensing / configuration
- ✅ **Self-contained HTML report** (score, evidence-backed findings, inventory)
- ✅ CLI (`aibom scan`) with JSON inventory, CycloneDX, HTML report, and severity exit codes
- ✅ Golden-fixture test suite

Roadmap → [SPEC.md](SPEC.md): dependency-graph visualization, plugin collectors.

## Install

```bash
# from PyPI
pip install aibom              # CLI only
pip install "aibom[server]"    # + the web API/UI (aibom serve)
```

```bash
# from source (uv recommended)
git clone https://github.com/d01ki/AIBOM-Inspector
cd AIBOM-Inspector
uv venv && uv pip install -e ".[dev]"
```

## Usage

```bash
# scan a repo and print the inventory
aibom scan ./path/to/repo

# write the full inventory (entities + relationships + evidence) as JSON
aibom scan ./path/to/repo --output inventory.json

# generate a CycloneDX 1.6 (ML-BOM) AIBOM — import it into Dependency-Track
aibom scan ./path/to/repo --cyclonedx aibom.cdx.json

# enrich Hugging Face models/datasets with hub metadata (license, formats, …)
aibom scan ./path/to/repo --resolve --cyclonedx aibom.cdx.json

# cache HF metadata for offline / air-gapped re-scans
aibom scan ./path/to/repo --resolve --hf-cache ~/.cache/aibom

# risk analysis: write a self-contained HTML report (score + findings + inventory)
aibom scan ./path/to/repo --report report.html

# CI gate: exit non-zero if any finding is at/above a severity
aibom scan ./path/to/repo --fail-on high

# drop low-confidence detections
aibom scan ./path/to/repo --min-confidence 0.8
```

## Risk rules & scoring

Findings are **deterministic and rule-based** (no LLM in the loop). Each carries a
severity, a `file:line` evidence trail, and a remediation.

| ID | Check | Default severity | Needs `--resolve` |
|---|---|---|---|
| TDR-001 | Pickle-based weight format (arbitrary code exec on load) | High | — |
| TDR-002 | Model reference without a pinned revision | Medium | — |
| TDR-003 | Name impersonates a popular model family (typosquat) | High | — |
| TDR-004 | Missing model card | Low | ✔ |
| TDR-005 | License missing / non-SPDX / unrecognized | Medium–Low | ✔ |
| TDR-006 | Very low adoption (verify author) | Medium | ✔ |
| TDR-007 | Hardcoded secret near an AI call | Critical | — |
| TDR-008 | Dataset with no provenance metadata | Low | — |
| TDR-009 | `trust_remote_code=True` | High | — |
| TDR-010 | Deprecated / superseded model referenced | Medium | — |

**Security score (0–100):** each of the four categories {integrity, provenance,
licensing, configuration} starts at 100 and loses points per finding
(critical 40 / high 20 / medium 10 / low 3, floored at 0); the overall score is
their mean. The formula is printed in the report itself for reproducibility.

Try it against the bundled deliberately-vulnerable demo app:

```bash
aibom scan tests/fixtures/vulnerable-ai-app
```

## Web app

Run the HTTP API + browser UI locally (paste a repo URL, get the AIBOM + score):

```bash
uv pip install -e ".[server]"     # or: pip install 'aibom[server]'
aibom serve                        # http://127.0.0.1:8000
```

The backend shallow-clones the URL into a throwaway temp dir, runs the same
static pipeline as the CLI, and returns JSON — it **never executes the cloned
code**. Clone URLs are validated against a host allowlist (github.com,
gitlab.com, bitbucket.org, codeberg.org) and passed to git as argv, not a shell
string.

| Endpoint | Purpose |
|---|---|
| `POST /api/scan` `{repo_url, resolve?}` | Inventory + CycloneDX + findings + score + dependency graph (JSON) |
| `POST /api/report` `{repo_url, resolve?}` | Self-contained HTML report |
| `GET /api/health` | Liveness + version |

The UI renders an interactive dependency graph from `/api/scan`'s `graph`
(`{nodes, edges}`): nodes are colored by their worst finding severity; click one
to see the component and its evidence trail.

## Deploy

The backend is a small container that serves the UI too, so one free service
runs the whole app from a single URL.

**Render (free, no credit card, recommended).** The scanner needs server-side
compute (it clones and analyzes repos), so it must run on a compute host — not a
static-only one. [`render.yaml`](render.yaml) is a blueprint: on
[render.com](https://render.com) → **New → Blueprint** → pick this repo → **Apply**.
A few minutes later the whole app (UI at `/`, API at `/api/*`) is live at
`https://aibom-inspector-api.onrender.com`. Free instances sleep after ~15 min
idle and cold-start on the next request.

**Run the image anywhere with Docker:**

```bash
docker build -t aibom .
docker run -p 8000:8000 aibom          # UI + API at http://localhost:8000
```

**Static-only hosts (GitHub Pages / HF *Static* Spaces).** These can host the
[`web/`](web/) UI for free, but **not** the scanner — point the UI's *API endpoint*
field at a compute backend (e.g. your Render URL) and set `AIBOM_CORS_ORIGINS` on
the backend to the UI's origin. [`.github/workflows/pages.yml`](.github/workflows/pages.yml)
publishes `web/` to Pages on push to `main` (enable *Settings → Pages → Source =
GitHub Actions*).

> **Note:** Hugging Face **Docker** Spaces now require a paid (PRO) plan; only
> **Static** Spaces are free. The Space frontmatter at the top of this README is
> kept for anyone on PRO — `git push` this repo to a Docker Space and it runs
> as-is. For a free deploy, use Render above.

- `AIBOM_CORS_ORIGINS` — comma-separated allowed origins (your Pages origin;
  defaults to `*` for local demos). Not needed if the backend also serves the UI.
- `AIBOM_WEB_DIR` — where the backend finds the UI to also serve at `/` (set in
  the image). Handy for an **all-in-one single-origin deploy with no CORS** —
  e.g. a Hugging Face Space serves both the UI and the API from one URL.

## What it detects (M1)

| Component | Signals |
|---|---|
| **Models** | `from_pretrained(...)`, `pipeline(model=...)`, `repo_id=`, `huggingface.co/...` URLs, LLM model ids (`gpt-*`, `claude-*`), and weight files (`.safetensors`, `.gguf`, `.pkl`, `.bin`, …) |
| **Datasets** | `load_dataset(...)` |
| **Prompts** | template files (`prompts/`, `*.prompt`, `*.jinja`), hardcoded system prompts |
| **Agents** | LangChain/LangGraph constructors (`create_react_agent`, `AgentExecutor`, …) |
| **Services** | provider SDK imports (`openai`, `anthropic`, …), explicit `base_url`, MCP server configs |

## Design principles

- **Static only.** The scanner reads text. It never imports, executes, or unpickles anything.
- **Evidence-backed.** Every entity carries `file:line` + the matched pattern + a confidence.
- **Deterministic.** Detection and (planned) scoring are rule-based and reproducible; LLM assistance is opt-in and limited to *explaining* findings, never producing them.
- **Local-first.** No SaaS, no telemetry, air-gap friendly.

## Development

```bash
uv run pytest            # tests
uv run ruff check .      # lint
uv run mypy              # types
```

### Releasing

Publishing is automated via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC — no tokens). One-time: add a trusted publisher on PyPI for this repo,
workflow `release.yml`, environment `pypi`. Then push a tag:

```bash
git tag v0.1.0 && git push origin v0.1.0   # builds, twine-checks, and publishes
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
