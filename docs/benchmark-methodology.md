# Benchmark methodology

`benchmark/evaluate.py` compares offline scans with manually curated ground
truth and produces JSON and Markdown reports.

## Matching

A component match requires the same normalized category and name. If ground
truth specifies a file and line, at least one evidence location must match it.
Each prediction and expected component can match at most once. Unmatched
predictions are false positives; unmatched expected components are false
negatives.

The report provides micro-averaged overall and category metrics. Categories
with no expected components and no predictions show `N/A`, not a perfect score.

## Scan mode

The harness scans with lockfile resolution **off**. Ground truth records the
components a repository declares; lockfile resolution correctly adds transitive
components that no hand-authored ground truth lists, and scoring those as false
positives would make precision meaningless. Lockfile coverage is exercised by
the unit tests (`tests/test_lockfiles.py`), not by this corpus.

## Reproducibility rules

- Public repositories must be pinned to immutable full commit SHAs.
- Ground truth must validate against the checked-in JSON Schema.
- Reviews must include negative repositories and production/test/example code.
- The evaluator never clones or executes repositories; checkout preparation is
  an explicit, auditable step.
- A checked-in synthetic fixture validates the harness but is not evidence of
  external-repository accuracy.

The external corpus (2026-10-18) has 20 manually reviewed, commit-pinned
repositories: 9 positive and 11 negative. Ground truth for the 13 newest
cases was written before the scanner ran on them, and that first run is
frozen:

| Run | Repos | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| First run on 13 unseen cases + 7 earlier (frozen: `reports/external-20-unseen.md`) | 20 | 0.913 | 0.661 | 0.767 | 84 | 8 | 43 |
| After fixing what that run exposed (`reports/external-latest.md`) | 20 | 0.966 | 0.869 | 0.915 | 113 | 4 | 17 |

Corrections to ground truth after the first run are limited to curation
mistakes against rules written down beforehand, and each is recorded in the
case's `notes` (see `benchmark/README.md`, *Protocol*).

## Inventory accuracy vs path accuracy

The corpus scores *component inventory* (models, services, prompts, packages).
It says nothing about exposure or impact *path* accuracy. Path behavior is
pinned separately by positive, negative and unknown fixtures:
`tests/test_cross_file_python.py`, `tests/test_cross_file_typescript.py` and
`tests/test_drift_identical_bom.py`. The two must never be reported as one
number.

Do not claim broad external-repository support until at least 20 pinned public
repositories, including negative cases, are present and reviewed.

## Agent-security extraction accuracy

`benchmark/agent_security/` scores the *static extraction* that agent
privilege-drift analysis builds on, against hand-reviewed ground truth on
pinned public repositories (`openai/openai-agents-python`,
`modelcontextprotocol/python-sdk`, `awslabs/mcp`). Verdicts are **not**
scored: public repositories ship no identity manifests or policies, so
`potentially_allowed` / `unknown` cannot be checked against reality.

```bash
# shallow clones at the pinned commits in cases*.json, under benchmark/checkouts/ (git-ignored)
python -m benchmark.agent_security.evaluate                                   # development cases
python -m benchmark.agent_security.evaluate --cases benchmark/agent_security/cases_heldout.json \
    --out benchmark/reports/agent-security-heldout-latest
```

The scanned code is parsed, never imported, installed or executed. The
evaluator refuses a checkout that is not at the pinned commit.

Six categories, each an exact set comparison:

| Category | Tuple |
|---|---|
| `agents` | `file:symbol` of each `Agent(...)` construction |
| `delegations` | parent source, child source, `handoff` / `agent_as_tool` |
| `mcp_server_tools` | server file, tool function |
| `mcp_connections` | agent source, transport |
| `server_links` | agent source, repository server file |
| `operations` | `file:tool`, IAM action |

### Two case sets, and which numbers count

* **Development cases** (`cases.json`, 5 cases). The ground truth was written,
  the tool was run, and the misses were then fixed. Their post-fix numbers
  are regression evidence, **not** an accuracy estimate.
* **Held-out cases** (`cases_heldout.json`, 2 cases). Ground truth was written
  and committed **before** the scanner was ever run on these paths. The first
  run is frozen in `reports/agent-security-heldout-first-run.*` and is the only
  independent measurement. Fixes made after looking at it turn later runs into
  regression evidence as well.

| Category | Dev, first run | Dev, after fixes | **Held-out, first run (frozen)** | Held-out, after fixes |
|---|---|---|---|---|
| agents | 1.0 / 0.937 | 1.0 / 1.0 | **1.0 / 1.0** (49) | 1.0 / 1.0 |
| delegations | 1.0 / 0.632 | 1.0 / 0.895 | **1.0 / 1.0** (3) | 1.0 / 1.0 |
| mcp_server_tools | n/a / 0.0 | 1.0 / 1.0 | **n/a / 0.0** (5) | 1.0 / 1.0 |
| mcp_connections | 0.4 / 0.4 | 0.9 / 0.9 | – | – |
| server_links | n/a / 0.0 | n/a / 0.0 | – | – |
| operations | n/a / 0.0 | 1.0 / 1.0 | **n/a / 0.0** (8) | 1.0 / 1.0 |

Precision / recall; held-out ground-truth sizes in parentheses; "–" means the
held-out set contains no items of that category. The held-out first run
missed every MCP tool and every operation of the awslabs CloudTrail server
because its tools are registered with `srv.tool(...)(self.method)` from a
class and use a `self._get_client()` factory; awslabs uses that registration
style in 16 of its 63 servers. That miss is the honest headline number.

Still missed after fixes (development set): agents passed to `clone(tools=[...])`
(2 delegations), a server list built dynamically (one connection reported as
`unknown` transport), and links from an agent to a repository server reached
over a URL (`server_links`, 3) — a URL cannot be statically tied to a file.

### Bias

* **The ground truth was written by the tool's author.** Ambiguous cases may be
  resolved in the tool's favor without anyone noticing. A second, independent
  reviewer has not checked these files yet.
* The held-out set is small (2 cases, 65 items) and all Python. It covers the
  OpenAI Agents SDK and one awslabs MCP server, not LangChain, CrewAI or
  TypeScript.
* Every precision of 1.0 rests on a small number of items. It shows that no
  false positives were seen on these cases. It is not a bound on the false-positive rate.

Do not quote the development-set numbers as accuracy. Quote the frozen
held-out first run, with its size and the author-bias caveat.
