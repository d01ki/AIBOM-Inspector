# Online enrichment

## Overview

Two opt-in network steps. The Hugging Face resolver adds license, author,
gated status, downloads, and formats to models and datasets (with an offline
cache via `--hf-cache`). The OSV mapper adds known-vulnerability findings for
pinned packages. Both are **off by default on the CLI** and on by default on
the API.

## Entry points

`aibom scan <t> --resolve [--vulns] [--hf-cache dir]`, and `POST /api/scan`
with `resolve` / `vulns` (default true).

## Source

`src/aibom/resolvers/**`, `src/aibom/vuln/**`.

## Depends on

Scan pipeline (entities to enrich) and network access to huggingface.co and
api.osv.dev.

## Normal paths

A cached HF snapshot enriches offline. OSV results become findings on the
matching package.

## Error paths

Network errors and rate limits leave entities unresolved without failing the
scan.

## Boundaries

`--hf-cache` without `--resolve` is offline-only. An unpinned package is not
sent to OSV.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_hf_resolver.py tests/test_osv.py` | parsing and mapping against stubbed clients (no network) |
| live `--resolve --vulns` scan | the real APIs still answer in the expected shape. **Manual**: it needs network and sends package names to third parties |

## Expected results

The unit tests pass. A live check is reported as NOT RUN unless a human ran it.

## Evidence

pytest output. For a live run, the command, its date, and the enriched fields.

## Known gaps / what usually breaks

Upstream API shape changes are only caught by the manual live check.

```json verify
{
  "id": "enrichment",
  "paths": [
    "src/aibom/resolvers/**",
    "src/aibom/vuln/**"
  ],
  "tests": [
    "tests/test_hf_resolver.py",
    "tests/test_osv.py"
  ],
  "smoke": [],
  "ui": [],
  "manual": [
    "Live `aibom scan tests/fixtures/vulnerable-ai-app --resolve --vulns` against huggingface.co and api.osv.dev (network; sends package and model names to third parties)."
  ]
}
```
