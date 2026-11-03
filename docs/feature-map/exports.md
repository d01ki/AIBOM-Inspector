# Exports & conformance

## Overview

The tool turns one scan into four artifacts: a CycloneDX 1.6 ML-BOM (with CISA
2026 minimum elements and declared known unknowns), SARIF 2.1.0 findings, a
self-contained HTML report, and an inventory JSON. `aibom conformance` scores
*any* CycloneDX document against the CISA 2026 minimum elements.

## Entry points

- CLI: `aibom scan <t> -c bom.json --sarif f.sarif -r report.html
  [--sbom-author/--sbom-supplier/--sbom-lifecycle] [--minimum-elements]`
- CLI: `aibom conformance bom.json [--fail-on-missing] [-o report.json]`
- API: `POST /api/report`, `/api/demo/report` (HTML), `/api/sarif`,
  `/api/demo/sarif`; `/api/scan` embeds `cyclonedx` and the conformance result.

## Source

`src/aibom/export/cyclonedx.py`, `export/sarif.py`, `report/html.py`,
`compliance/minimum_elements.py`, `spdx.py`.

## Depends on

Scan pipeline, plus the dependency map for CycloneDX `dependencies`.

## Normal paths

The BOM validates against the official CycloneDX 1.6 schema. Every component
has a `dependencies` entry rooted at the primary component. SARIF uploads to
GitHub Code Scanning. The report renders with no external assets.

## Error paths

`aibom conformance` on a non-CycloneDX or unreadable file: a clean error, not a
traceback. `--fail-on-missing` exits 1 when a required element is silently
absent, but a *declared* unknown does not fail.

## Boundaries

An empty inventory still yields a valid BOM with only the primary component.
Prompt bodies never appear in any artifact (hashes only).

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_cyclonedx.py tests/test_cyclonedx_schema.py tests/test_sarif.py tests/test_minimum_elements.py` | schema validity, the property mapping, the SARIF shape, conformance logic |
| smoke: scan → `-c/--sarif/-r` → `conformance --fail-on-missing` | the artifacts are produced end to end and the tool's own BOM conforms |

## Expected results

Every exit code is 0, all three files exist, and `conformance` reports no
missing elements on the tool's own output.

## Evidence

The generated `bom.json`, `findings.sarif`, `report.html`, and conformance
stdout, saved in the run's evidence directory.

## Known gaps / what usually breaks

Schema validation needs the `cyclonedx-python-lib[validation]` dev extra. When
it is absent, the schema test is skipped, which the verify script reports as
NOT RUN rather than PASS.

```json verify
{
  "id": "exports",
  "paths": [
    "src/aibom/export/**",
    "src/aibom/report/**",
    "src/aibom/compliance/**",
    "src/aibom/spdx.py"
  ],
  "tests": [
    "tests/test_cyclonedx.py",
    "tests/test_cyclonedx_schema.py",
    "tests/test_sarif.py",
    "tests/test_minimum_elements.py"
  ],
  "smoke": [
    {
      "name": "scan writes CycloneDX, SARIF and HTML",
      "cmd": ["{py}", "-m", "aibom.cli", "scan", "tests/fixtures/vulnerable-ai-app", "-q",
              "-c", "{out}/bom.json", "--sarif", "{out}/findings.sarif", "-r", "{out}/report.html"],
      "expect_exit": 0,
      "expect_files": ["{out}/bom.json", "{out}/findings.sarif", "{out}/report.html"]
    },
    {
      "name": "own BOM passes CISA 2026 conformance",
      "cmd": ["{py}", "-m", "aibom.cli", "conformance", "{out}/bom.json", "--fail-on-missing"],
      "expect_exit": 0
    }
  ],
  "ui": [],
  "manual": []
}
```
