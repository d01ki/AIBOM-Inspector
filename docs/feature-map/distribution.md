# Distribution

## Overview

How users get and run the tool:

- the wheel (`pyproject.toml`, with the web UI and demo fixtures force-included)
- the Docker image and `docker-compose.yml`
- the `./aibom` / `aibom.ps1` launchers
- Cloud Run (`scripts/deploy-cloud-run.sh`)
- the GitHub Actions workflows: `ci.yml` (lint, types, tests on 3.10–3.12,
  the Docker image check, the browser check),
  `release.yml`, and `deploy-cloud-run.yml`, which
  deploys each `main` commit that passed CI to the public Cloud Run site
  (keyless, Workload Identity Federation; skipped until the `GCP_*`
  repository variables exist; setup in `docs/CLOUD_RUN_DEPLOYMENT.md`)

## Entry points

`pip install aibom[server]`, `./aibom …`, `docker compose …`, and the
workflows on push, PR, or manual dispatch.

## Source

`pyproject.toml`, `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `aibom`,
`aibom.ps1`, `scripts/deploy-cloud-run.sh`, `scripts/verify_docker.py`,
`.github/workflows/*`.

## Depends on

Every feature, since this is what ships them.

## Normal paths

CI passes on all three Python versions. The image builds, and the same image
serves the UI and API locally (port 8000) and Cloud Run-shaped (`$PORT=8080`,
read-only root filesystem, 1 vCPU, 1 GiB), runs the CLI against a read-only
mount, and stops gracefully on SIGTERM. The launchers rebuild the image on
every run (a cache hit when nothing changed).

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
| `pytest tests/test_distribution.py` | without Docker: every wheel input is copied into the image, `.dockerignore` hides nothing the Dockerfile copies, uvicorn is PID 1, the user is not root |
| `python scripts/verify_docker.py [out]` | with Docker (CI job `docker`): build, local run, CLI, Compose config, Cloud Run shape, SIGTERM; evidence in `<out>/docker-verify.json` |
| releases, Cloud Run | **Human approval required**: these are outward-facing, never run by an agent. Merging to `main` deploys Cloud Run once the `GCP_*` variables are set, so a merge needs the same approval |

## Expected results

Lint and types are clean. Manual items are NOT RUN unless a human ran them.

## Evidence

The ruff and mypy logs. For manual items, the person, the date, and the
command.

## Known gaps / what usually breaks

- Windows writes CRLF by default. Check `git ls-files --eol` before committing
  new files.
- A stale image. The launchers built the image only when it was missing, so
  after a `git pull` `./aibom ui` kept serving the old code. They now run
  `docker build -q` every time (about a second when nothing changed), except
  for an image the caller named with `AIBOM_IMAGE`.
- Output paths. The launchers mount the current directory read-only at
  `/work`, so `./aibom scan . -c bom.json` failed with "Read-only file system"
  although the header promises reports in `./aibom-out`. Values of the output
  flags (`-o -c -r --sarif --agent-sarif --minimum-elements --output-dir
  --hf-cache`, also as `--flag=value`) now map to `/out`, parents are created
  on the host, and a path outside `./aibom-out` is refused with a message.
  `test_both_launchers_send_the_same_outputs_to_aibom_out` keeps the two
  launchers' lists equal and real; the behavior itself needs Docker
  (run `./aibom scan . -c bom.json` and `.\aibom.ps1 scan . -c bom.json`).
- The build context. There was no `.dockerignore`, so `docker build` sent
  `.venv`, `benchmark/checkouts` and `verify-out` (about 1 GB) to the
  daemon on every build. `test_dockerignore_*` hold both directions: the
  heavy directories stay out, and nothing the Dockerfile copies (the demo's
  `uv.lock` included) is hidden.
- PID 1. `sh -c "uvicorn …"` left `sh` as PID 1 unless the shell happened to
  exec; the CMD now says `exec`, so SIGTERM from `docker stop` or Cloud Run
  reaches uvicorn (`test_the_server_is_pid_1`, and the SIGTERM check in
  `verify_docker.py`).
- Dependency layer. Source was copied before `pip install`, so every code
  change reinstalled FastAPI and the rest. Dependencies are now installed
  from `pyproject.toml` in their own layer, and the wheel is built in a
  separate stage, so the runtime image carries no source tree.

```json verify
{
  "id": "distribution",
  "paths": [
    "pyproject.toml",
    "Dockerfile",
    ".dockerignore",
    "scripts/verify_docker.py",
    "docker-compose.yml",
    "aibom",
    "aibom.ps1",
    ".github/workflows/*"
  ],
  "tests": [
    "tests/test_feature_map.py",
    "tests/test_distribution.py"
  ],
  "smoke": [],
  "ui": [],
  "manual": [
    "python scripts/verify_docker.py verify-out/docker (needs Docker; CI runs it as the docker job).",
    "Release / Cloud Run deployment: human approval required; never run by an agent."
  ]
}
```
