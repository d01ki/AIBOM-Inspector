# Web UI

## Overview

A single dependency-free HTML file (`web/index.html`, about 3,500 lines) that
drives the API. It contains the scan form, the result tabs (agent security,
findings, Dependencies, inventory, exports), the compare and drift view, and
the hero demos. It also works when served from GitHub Pages with a separate
backend (`?api=`).

## Entry points

`aibom serve`, then `http://localhost:8000/`. `?repo=<url>` pre-fills the
form and starts the scan, `?demo=1` runs the bundled demo, and `?api=<url>`
selects a backend.

## Source

`web/index.html`.

## Depends on

The HTTP API response shapes (`graph`, `findings`, `inventory`,
`agent_security`, `cyclonedx`, and the drift payloads).

## Normal paths

Scan → results visible → Dependencies tab draws directed, typed edges →
clicking a node lists its connections with evidence.

## Error paths

A backend error shows a status message, not a blank page. A missing DOM id
must not throw at load (guarded by `tests/test_web_ui.py`).

## Boundaries

An empty graph shows "No components to graph." and hides the legends. Long
labels are truncated with `…`.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_web_ui.py` | structural guards: no dangling `$("id")`, results not hidden by CSS |
| `python scripts/verify_ui.py --fixture <f>` | headless Chromium: real render, edge arrows, legend, panel text, no console errors, plus a screenshot |
| a human looks at the screenshot | layout and readability. **Manual** |

## Expected results

The verify_ui JSON shows `"status": "PASS"`, `edges == edges_with_arrow`, and
`console_errors == []`.

## Evidence

`verify-out/<run>/ui-<fixture>.png` and `.json`.

## Known gaps / what usually breaks

The page has no JS unit-test harness. Behavior is only proven by the
browser run. The attack-path visualization (impact and exposure paths) is not
yet covered by a browser check.

```json verify
{
  "id": "web-ui",
  "paths": [
    "web/**",
    "scripts/verify_ui.py"
  ],
  "tests": [
    "tests/test_web_ui.py"
  ],
  "smoke": [],
  "ui": ["vulnerable-ai-app", "vulnerable-ts-agent", "demos"],
  "manual": [
    "A human reviews the screenshot for layout and readability."
  ]
}
```
