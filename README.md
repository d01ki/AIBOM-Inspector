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

- ✅ **Python AST detectors** for OpenAI, Anthropic, and Hugging Face usage,
  including import aliases, actual API invocations, and auditable value resolution
- ✅ **Usage and reachability evidence** — declared/imported/instantiated/invoked
  states, same-file entrypoint paths, confidence factors, detector IDs, and
  production/test/example/docs source contexts
- ✅ **Prompt source-to-sink analysis** — OpenAI/Anthropic prompt arguments,
  Assistants instructions, bounded HTTP/CLI/environment data-flow paths, trust
  boundaries, and secret-safe prompt hashes
- ✅ **Reproducible benchmark harness** — category Precision/Recall/F1 plus
  explicit false-positive and false-negative reports
- ✅ **Dependency-manifest collector** — finds AI/ML libraries in `requirements*.txt`,
  `pyproject.toml`, `Pipfile`, `package.json` (PyPI + npm) with versions and purls, so
  the AIBOM is useful on real repos, not just ones with inline `from_pretrained`
- ✅ **Vulnerability mapping** — with `--resolve`, pinned packages are checked against
  [OSV.dev](https://osv.dev) and matching CVE/GHSA advisories become evidence-backed findings
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
- ✅ **Deterministic risk rules (TDR-001…012 and AIBOM-PROMPT-004)** + a
  reproducible 0–100 security score over integrity / provenance / licensing /
  configuration
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

# online enrichment: Hugging Face metadata (license, formats, …) AND OSV
# vulnerability mapping for pinned AI packages
aibom scan ./path/to/repo --resolve --cyclonedx aibom.cdx.json

# cache HF metadata for offline / air-gapped re-scans
aibom scan ./path/to/repo --resolve --hf-cache ~/.cache/aibom

# risk analysis: write a self-contained HTML report (score + findings + inventory)
aibom scan ./path/to/repo --report report.html

# CI gate: exit non-zero if any finding is at/above a severity
aibom scan ./path/to/repo --fail-on high

# drop low-confidence detections
aibom scan ./path/to/repo --min-confidence 0.8

# disable one detector while debugging or enforcing an organization profile
aibom scan ./path/to/repo --disable-detector python.openai.ast

# evaluate checked-out repositories against reviewed ground truth
python benchmark/evaluate.py
```

The reproducible reports include a deterministic local fixture and a
[two-repository public evaluation](benchmark/reports/external-latest.md). The
current pinned set records precision/recall/F1 of 1.0000 with no mismatches. It
is regression evidence, not a claim of broad ecosystem coverage.

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
| TDR-011 | MCP server exposes an LLM-invokable tool surface | Low | — |
| TDR-012 | AI package declared without a pinned version | Low | — |
| AIBOM-PROMPT-004 | Untrusted input flows into system/developer instructions | High | — |
| OSV-* | Known vulnerability in a pinned AI package (OSV.dev) | per advisory | ✔ (network) |

**Security score (0–100):** each of the four categories {integrity, provenance,
licensing, configuration} starts at 100 and loses points per finding
(critical 40 / high 20 / medium 10 / low 3, floored at 0, counting at most
3 findings per rule). The overall score is `0.55 × mean + 0.45 × worst category`,
so one wrecked category cannot be averaged away by categories with no components.
An empty inventory renders as "no AI components detected", not as 100/A. The
formula is printed in the report itself for reproducibility.

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

The backend is a small container that serves the UI too, so one service runs
the whole app from a single URL.

**AWS Lightsail (production).** Pushes to `main` run
[`deploy.yml`](.github/workflows/deploy.yml), connect to the configured
Lightsail instance, and execute `/usr/local/bin/deploy-aibom`. The production
UI and API are served together at [aibom-inspector.com](https://aibom-inspector.com/).

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
[`web/`](web/) UI for free, but **not** the scanner — open the page with
`?api=https://your-backend` so it talks to a compute backend (e.g. your Render
URL), and set `AIBOM_CORS_ORIGINS` on the backend to the UI's origin. Served by
the backend itself, the UI needs no configuration at all.
The optional [`.github/workflows/pages.yml`](.github/workflows/pages.yml) is
manual-only so it does not conflict with the Lightsail deployment. Before
running it, enable *Settings → Pages → Source = GitHub Actions*.

> **Note:** Hugging Face **Docker** Spaces now require a paid (PRO) plan; only
> **Static** Spaces are free. The Space frontmatter at the top of this README is
> kept for anyone on PRO — `git push` this repo to a Docker Space and it runs
> as-is. For a free deploy, use Render above.

- `AIBOM_CORS_ORIGINS` — comma-separated allowed origins (your Pages origin;
  defaults to `*` for local demos). Not needed if the backend also serves the UI.
- `AIBOM_WEB_DIR` — where the backend finds the UI to also serve at `/` (set in
  the image). Handy for an **all-in-one single-origin deploy with no CORS** —
  e.g. a Hugging Face Space serves both the UI and the API from one URL.

## What it detects

| Component | Signals |
|---|---|
| **Models** | Python AST-confirmed OpenAI/Anthropic calls, `from_pretrained(...)`, `pipeline(model=...)`, variables/dictionaries/f-strings/environment defaults, `repo_id=`, HF URLs, and weight files (`.safetensors`, `.gguf`, `.pkl`, `.bin`, …) |
| **Datasets** | `load_dataset(...)` |
| **Prompts** | template files, hardcoded system prompts, OpenAI Responses/Chat/Completions/Assistants and Anthropic Messages/Completions sinks, with bounded source-to-sink paths for HTTP, CLI, environment, file, retrieval, and database inputs |
| **Agents** | LangChain/LangGraph constructors (`create_react_agent`, `AgentExecutor`, …) |
| **Services** | provider SDK imports in Python **and JS/TS** (`openai`, `anthropic`, `@anthropic-ai/sdk`, …), explicit `base_url`, MCP client configs (`mcpServers`), **MCP server implementations** (Python `mcp`/`FastMCP`, TS `@modelcontextprotocol/sdk`) |
| **Packages** | **every** dependency declared in `requirements*.txt`, `pyproject.toml`, `Pipfile`, `package.json` (PyPI + npm), with version + purl — a complete BOM. AI/ML-ecosystem packages (incl. `mcp`/`fastmcp`/`@modelcontextprotocol/*`) are flagged `ai`, and that AI layer is what the risk rules, graph, and score focus on |

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
python benchmark/evaluate.py  # precision/recall benchmark
```

Implementation details: [architecture](docs/architecture.md),
[detection methodology](docs/detection-methodology.md),
[benchmark methodology](docs/benchmark-methodology.md), and
[known limitations](docs/limitations.md).

### Releasing

Publishing is automated via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC — no tokens). One-time: add a trusted publisher on PyPI for this repo,
workflow `release.yml`, environment `pypi`. Then push a tag:

```bash
git tag v0.1.0 && git push origin v0.1.0   # builds, twine-checks, and publishes
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
