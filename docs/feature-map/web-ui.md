# Web UI

## Overview

A dependency-free page with no build step (`web/index.html`, `app.css`,
`app.js`) that drives the API. It contains the scan form, the result tabs (agent security,
findings, Dependencies, inventory, exports), the compare and drift view, and
the hero demos. The page is served by the API server and calls only its own
origin; there is no separate backend to select.

## Entry points

`aibom serve`, then `http://localhost:8000/`. `?repo=<url>` pre-fills the
form and starts the scan, and `?demo=1` runs the bundled demo.

## Source

`web/index.html`, `web/app.css`, `web/app.js`, `web/favicon.svg`.

## Depends on

The HTTP API response shapes (`graph`, `findings`, `inventory`,
`agent_security`, `cyclonedx`, and the drift payloads).

## Normal paths

Scan → results visible → Dependencies tab draws directed, typed edges →
clicking a node lists its connections with evidence.

## Error paths

A server error shows a status message, not a blank page. With no server
behind the page (opened from a file or a static host) the `/api/health` check
on load says so, and `?repo=` / `?demo=1` do not start. A missing DOM id must
not throw at load (guarded by `tests/test_web_ui.py`).

## Boundaries

An empty graph shows "Nothing to map." and hides the legends. Long labels are
truncated with `…`. Packages that depend on each other (a cycle in the
lockfile) still get a finite layered layout.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_web_ui.py` | structural guards: no dangling `$("id")`, results not hidden by CSS |
| `python scripts/verify_ui.py --fixture <f>` | headless Chromium: real render, edge arrows, legend, panel text, no console errors, plus a screenshot |
| `python scripts/verify_ui.py --fixture demos` | every demo, both viewports, the package graph, the translation marks, a cyclic layout, and the injection replay |
| a human looks at the screenshot | layout and readability. **Manual** |
| a human translates the page in a browser | the translation itself: headless Chromium has no translator, so the check only proves the page allows it and which elements opt out. **Manual** |

## Expected results

The verify_ui JSON shows `"status": "PASS"`, `edges == edges_with_arrow`, and
`console_errors == []`.

## Evidence

`verify-out/<run>/ui-<fixture>.png` and `.json`.

## Known gaps / what usually breaks

The page has no JS unit-test harness. Behavior is only proven by the
browser run. The attack-path visualization (impact and exposure paths) is not
yet covered by a browser check.

The page is `web/index.html` + `app.css` + `app.js` (+ `favicon.svg`), served
side by side with no build step; the structural test reads all three. The UI
text is English; a browser may translate it.

Progress: a repository scan reads `/api/scan/stream` and lists each stage as
the server reports it; Cancel closes the stream, which stops the server-side
scan at the next stage. The page ships with its server, so it has no fallback
to the plain `/api/scan` (which stays for API clients).

What broke before, and the check that now holds it:

- The whole page opted out of translation (`translate="no"` on `<html>` and
  the `notranslate` meta), so a browser's Translate did nothing. The opt-out
  now sits on identifiers only: `app.js` marks every `<code>`, `<pre>` and
  `<svg>` as it enters the page, and names outside `<code>` carry
  `translate="no"` in their template. A new template that prints a
  repository-controlled name outside `<code>` needs the attribute (or
  `verbatim()`); `verify_ui.py --fixture demos` fails when a `<code>`, a graph
  or a package/component name is left open.
- A "Backend address" field and `?api=<url>` let a link point the page at any
  server: the repository URL went there and its reply was drawn as the result.
  It existed for a statically hosted copy of the page. Both are gone, `api()`
  is the only function that calls `fetch`, and `tests/test_web_ui.py` fails on
  a second caller or an absolute API URL.
- A lockfile with two packages that depend on each other made the package
  graph's height `NaN` (the cycle climbed to the depth cap and left empty
  columns). `layerLayout` numbers only the depths in use; the demos check lays
  out a cyclic graph in the browser.
- Dragging a node moved its label 4 px up, because drag and draw computed the
  label position separately; both use `labelY()`.
- `verify_ui.py` went to `/#compare` three times in a row. That does not
  reload the page, so the previous demo's result satisfied the next demo's
  wait and the MCP demo was measured on the privilege-drift graph. Each demo
  now starts from a reloaded page (`_open`).

- `esc()` escaped `<` and `&` but not quotes, so a repository file named
  `a" onfocus="…` broke out of an `aria-label` in the Compare view (HTML
  injection on the app's origin). `esc()` now escapes `"` and `'` as well, the
  server sends a CSP without inline script, and `verify_ui.py --fixture demos`
  replays every demo with an HTML payload appended to each repository-controlled
  string and fails if any view renders it as markup.
- A critical finding read as a pass because "76 / B" was the biggest thing on
  screen. The summary leads with the API's `headline`; the score sits in a
  collapsed "secondary" disclosure. `verify_ui.py --fixture demos` fails if the
  sample is not headed "Action required".
- The map shrank to an unreadable 351 px on a phone, and tabs scrolled out of
  view. The demos check loads the sample at 403 px and 1280 px and fails on
  page-level sideways scroll, a tab off screen, or a map label under 9 px.
- Bigger node labels moved the centre of a node group into empty space, so
  clicking the group missed; the check clicks the node's circle.
- "No edges" looked like "no dependencies". The Dependencies tab renders the
  API's full `dependencies` table and says "relations unresolved" when no
  edge-recording lockfile exists; the map says when it has nothing to connect.
- A real-size AI usage map (`vercel/ai-chatbot`: 34 components, long
  `system-prompt@…` labels) drew 17 pairs of overlapping labels: the force
  layout kept circles apart on a fixed 800×520 canvas and ignored label width.
  `spreadLabels()` pushes apart nodes whose circle-plus-label boxes meet and
  grows the map downwards only (sideways growth would shrink the text under
  the default zoom). `verify_ui.py --fixture demos` draws a synthetic map of
  the same shape and fails on any overlapping label pair (`dense-map`).

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
