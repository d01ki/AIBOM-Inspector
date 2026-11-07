# HTTP API

## Overview

A FastAPI app (`aibom serve`, the Docker image, render.com) that shallow-clones
a public repository URL into a temporary directory, runs the same pipeline as
the CLI, and returns JSON or HTML. It also serves the web UI from `/`.

## Entry points

`GET /api/health`; `POST /api/scan`, `/api/scan/stream`, `/api/demo`, `/api/agent-drift/demo`,
`/api/report`, `/api/demo/report`, `/api/diff`, `/api/diff/demo`,
`/api/sarif`, `/api/demo/sarif`.

## Source

`src/aibom/server/app.py`, `src/aibom/server/clone.py`, `src/aibom/server/__init__.py`.

## Depends on

Scan pipeline, Exports, Drift, Agent security. `git` is needed for real clones.

## Normal paths

A valid GitHub URL is cloned shallowly, scanned, and cleaned up. A demo
endpoint works with no network. `/api/scan/stream` runs the same scan in a
worker thread and streams NDJSON: `{"stage": id}` as each step starts (`clone`,
`collect`, `lockfiles`, `link`, `resolve`, `risk`, `vulns`, `agents`,
`report`; skipped steps are not sent), then `{"result": payload}`. When the
client disconnects, the worker stops at the next stage boundary.

## Error paths

A non-HTTPS or non-allowlisted URL, an SSRF-style host, a missing ref, or a
clone timeout returns 4xx with an actionable message. Clone errors never leak
the temp path. On the stream, a bad URL is still a plain 400 before streaming;
a clone failure after streaming started is an `{"error", "status"}` line.

## Boundaries

`min_confidence` is limited to 0–1. CORS origins come from
`AIBOM_CORS_ORIGINS` (default `*`).

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_server.py tests/test_clone.py` | every route with a fake cloner, plus URL validation and clone limits |
| `python scripts/verify_ui.py` (uses the real app over HTTP) | the app serves the UI and `/api/scan` through uvicorn |
| live clone of a public repo | **Manual**: needs network |

## Expected results

All route tests pass. A live clone is NOT RUN unless a human ran it.

## Evidence

pytest output, and the UI run's JSON (the scan went through the real HTTP
stack).

## Known gaps / what usually breaks

Changing a response key breaks the UI silently. Run the Web UI checks with any
API change. A new scan stage must be added to `STAGES` in `web/app.js`; `tests/test_web_ui.py`
compares the two lists.
The browser check intercepts both `/api/scan` and `/api/scan/stream` to keep
the run offline: a new scan route needs the same interception.

```json verify
{
  "id": "server-api",
  "paths": [
    "src/aibom/server/**"
  ],
  "tests": [
    "tests/test_server.py",
    "tests/test_clone.py"
  ],
  "smoke": [],
  "ui": ["vulnerable-ai-app"],
  "manual": [
    "Live `POST /api/scan` with a real public GitHub URL (network, git clone)."
  ]
}
```
