# Distribution

## Overview

How users get and run the tool:

- the wheel (`pyproject.toml`, with the web UI and demo fixtures force-included)
- the Docker image and `docker-compose.yml`
- the `./aibom` / `aibom.ps1` launchers
- the render.com blueprint, and Cloud Run (`scripts/deploy-cloud-run.sh`)
- the GitHub Actions workflows: `ci.yml` (lint, types, tests on 3.10–3.12),
  `release.yml`, `pages.yml` (manual), and `deploy-cloud-run.yml`, which
  deploys each `main` commit that passed CI to the public Cloud Run site
  (keyless, Workload Identity Federation; skipped until the `GCP_*`
  repository variables exist; setup in `docs/CLOUD_RUN_DEPLOYMENT.md`)

## Entry points

`pip install aibom[server]`, `./aibom …`, `docker compose …`, and the
workflows on push, PR, or manual dispatch.

## Source

`pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `aibom`, `aibom.ps1`,
`render.yaml`, `scripts/deploy-cloud-run.sh`, `.github/workflows/*`.

## Depends on

Every feature, since this is what ships them.

## Normal paths

CI passes on all three Python versions. The image builds and `./aibom demo`
runs inside it.

## Error paths

A force-included path that no longer exists breaks the wheel build.

## Boundaries

Python 3.10 is the floor. Use only 3.10-compatible syntax (checked by ruff
`target-version` and the CI matrix).

## How to verify

| Check | Proves |
|---|---|
| `ruff check .` and `mypy` | the same gates CI runs |
| `pytest tests/test_feature_map.py` | the feature map still covers every shipped source file |
| Docker build plus `./aibom demo` | **Manual**: slow, needs Docker |
| releases, Pages deploys, render.com, Cloud Run | **Human approval required**: these are outward-facing, never run by an agent. Merging to `main` deploys Cloud Run once the `GCP_*` variables are set, so a merge needs the same approval |

## Expected results

Lint and types are clean. Manual items are NOT RUN unless a human ran them.

## Evidence

The ruff and mypy logs. For manual items, the person, the date, and the
command.

## Known gaps / what usually breaks

Windows writes CRLF by default. Check `git ls-files --eol` before committing
new files.

```json verify
{
  "id": "distribution",
  "paths": [
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    "aibom",
    "aibom.ps1",
    "render.yaml",
    ".github/workflows/*"
  ],
  "tests": [
    "tests/test_feature_map.py"
  ],
  "smoke": [],
  "ui": [],
  "manual": [
    "docker build . and ./aibom demo inside the image (needs Docker).",
    "Release / Pages / render.com deployment: human approval required; never run by an agent."
  ]
}
```
