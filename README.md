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

**Early alpha (v0.1, M1).** Implemented today:

- ✅ Unified Pydantic schema with mandatory evidence
- ✅ Static repository collector (models, datasets, prompts, agents, services)
- ✅ Deduplicating inventory + typed relationship graph
- ✅ CLI (`aibom scan`) with JSON inventory export
- ✅ Golden-fixture test suite

Roadmap → [SPEC.md](SPEC.md): Hugging Face resolution, CycloneDX 1.6 export,
deterministic risk rules (TDR-001…010) + scoring, HTML report, graph dashboard.

## Install

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

# drop low-confidence detections
aibom scan ./path/to/repo --min-confidence 0.8
```

Try it against the bundled deliberately-vulnerable demo app:

```bash
aibom scan tests/fixtures/vulnerable-ai-app
```

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

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Prior art & credits

Builds on ideas from OWASP CycloneDX ML-BOM, Dependency-Track, and the pickle-safety
work in `protectai/modelscan` and `mmaitre314/picklescan`.
