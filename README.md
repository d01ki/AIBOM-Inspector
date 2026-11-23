# AIBOM Inspector

**Find the AI in a repository and what an attacker could make it do.**

An SBOM or AI-BOM lists components. It cannot show that an agent's privileges
or exposure changed while the component list stayed the same. AIBOM Inspector
is an open-source, evidence-driven AI supply chain security analyzer. It
inventories models, SDKs, prompts, agents, MCP servers and every dependency as
a CycloneDX AI-BOM, then correlates each agent with the tools it binds and the
privileged operations those tools perform. It reports untrusted input that
crosses into those tools, and security drift between two revisions. Every
claim is traced to a `file:line`. It never executes the scanned code or loads
a model.

[![CI](https://github.com/d01ki/AIBOM-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/d01ki/AIBOM-Inspector/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

## Demo

[![Watch the AIBOM Inspector demo on YouTube](https://img.youtube.com/vi/BPWNt6KgGvY/maxresdefault.jpg)](https://youtu.be/BPWNt6KgGvY)

▶ **Video:** <https://youtu.be/BPWNt6KgGvY> · **Try it in the browser:** <https://aibom-inspector.com/>
(click *Try the bundled sample*; no URL or sign-in needed)

## The problem, in one pull request

A pull request changes one line of a prompt template. The model, the SDK and
every package stay the same, so an SBOM diff reports **no change**.
AIBOM Inspector reports that user input now reaches the instructions of an
agent whose tool runs shell commands, a path that did not exist before:

```
HTTP request body   routes/api.py:11
  → system prompt   prompts/builder.py:8
  → agent           assistant/main.py:9
  → bound tool      tools/executor.py:16   → subprocess (shell command)
```

> **An AIBOM does not change. The attack surface does.**

`aibom diff --fail-on high` turns that into a CI failure.

## What it does

- **Inventory (AI-BOM):** AI models, datasets, prompts, agents, MCP servers
  and providers in Python and TypeScript/JavaScript, plus every package across
  PyPI, npm, Go, crates.io, Maven, RubyGems, Packagist and NuGet, with a
  dependency graph drawn from the lockfile (npm, pnpm, yarn, uv, poetry,
  Pipfile, Cargo, composer, Gemfile; each arrow cites its line).
- **Attack paths:** follows untrusted input (HTTP, CLI, env, files,
  retrieval) through prompts into a tool bound to an agent, and into what the
  tool does: shell, file writes, network. Each path is labelled
  *proven statically* or *potential*.
- **Agent privileges:** links each agent (Python OpenAI Agents SDK, with the
  MCP servers it connects to) to its bound tools, the operations they perform
  (shell, file writes, network, and AWS SDK calls mapped to IAM actions) and,
  when the repository
  declares one in `aibom-identity.yaml`, the cloud identity and IAM policy it
  runs under. Without a declared identity, a permission verdict is `unknown`,
  never guessed. See [Agent privilege drift](docs/agent-privilege-drift.md).
- **Security drift analysis:** compares two revisions and reports new
  input-to-tool paths, and agent cloud permissions that grow (IAM policy or
  MCP tool filter), even when the component list stays identical.
- **Known vulnerabilities:** OSV.dev advisories merged across GHSA, PYSEC and
  CVE aliases, with one upgrade per package that clears every advisory with
  a known fixed release.
- **Standard outputs:** CycloneDX 1.6 ML-BOM (checked against the
  [CISA 2026 SBOM minimum elements](docs/cisa-2026-minimum-elements.md)),
  SARIF for GitHub code scanning, an HTML report and JSON.

Rules are deterministic, with no LLM in the loop, and are mapped to the
OWASP Top 10 for LLM Applications. Every finding carries file and line
evidence and a remediation.

**Measured, not claimed:** on 20 pinned public repositories with ground truth
written before scanning, detection precision is 0.97 and recall 0.87
([report](benchmark/reports/external-latest.md)). Attack paths and agent
privilege drift are demonstrated on the bundled scenarios. On the 26 public
repositories in our local corpus the scanner finds models, prompts, tools and
MCP servers, one prompt-exposure finding, and no complete input-to-tool path.
None of them ships an identity manifest, so permission verdicts there stay
`unknown`.

## Try it locally

```bash
git clone https://github.com/d01ki/AIBOM-Inspector && cd AIBOM-Inspector
./aibom demo        # offline: sample scan + same-components drift demo
./aibom ui          # web UI at http://localhost:8000
./aibom scan https://github.com/owner/repo
./aibom diff baseline/ candidate/ --fail-on high
```

`./aibom` builds the Docker image from your checkout and runs it (Windows:
`.\aibom.ps1`); after a `git pull` it rebuilds only what changed. Compose works
too: `docker compose up` serves the UI at <http://localhost:8000>. Without
Docker: `pip install -e ".[server]"` (Python 3.10+), then `aibom scan .` or
`aibom serve`. The same image runs on Cloud Run
([deployment](docs/CLOUD_RUN_DEPLOYMENT.md)).

## Documentation

- [Usage](docs/usage.md): CLI, configuration, risk rules and scoring,
  web app and API, what it detects
- [Architecture](docs/architecture.md) ·
  [Detection methodology](docs/detection-methodology.md) ·
  [Agent privilege drift](docs/agent-privilege-drift.md)
- [Benchmark](docs/benchmark-methodology.md): 20 pinned public repositories,
  ground truth written before scanning ·
  [Known limitations](docs/limitations.md) ·
  [Writing a detector](docs/contributing-detectors.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
