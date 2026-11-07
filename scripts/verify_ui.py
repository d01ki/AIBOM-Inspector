"""Drive the real web UI against a local fixture and capture evidence.

Starts the FastAPI app (UI + API) in-process on a free port, with the repo
cloner replaced by a read-only copy of a local fixture, so no network is used.
A headless Chromium then loads ``/?repo=...`` (which starts the scan), opens the
Dependencies tab, selects the best-connected node, and records:

* ``<out>/ui-<fixture>.png``      - screenshot of the dependency graph
* ``<out>/ui-<fixture>.json``     - DOM measurements + console errors + status

``--fixture demos`` instead clicks the bundled offline demos (sample scan,
privilege drift, MCP tool exposure, compare) and checks that each one draws a
dependency map with directed, evidence-labelled edges
(``<out>/ui-demos-<demo>.png`` and ``<out>/ui-demos.json``). It then loads the
sample at 403 px and 1280 px wide and checks the page does not scroll
sideways, every result tab is on screen, and map labels stay readable
(``<out>/ui-demos-viewport-<width>.png``). The sample's Dependencies tab must
draw one node per package and one lockfile-cited arrow per recorded dependency
(``<out>/ui-demos-dependency-graph.png``). Finally it replays the demos with
every repository-controlled string in the API responses carrying an HTML
payload, and fails if any view renders it as markup (escaping regression).

A fixture run also checks that the scan went through ``/api/scan/stream`` and
that the backend reported its stages.

Exit code: 0 PASS, 1 FAIL (an assertion about the page failed), 2 BLOCKED
(Playwright or a browser is unavailable). Never reports PASS for a check it
could not run.

Usage::

    python scripts/verify_ui.py --fixture vulnerable-ai-app --out verify-out
"""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

PASS, FAIL, BLOCKED = 0, 1, 2


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _serve(fixture: Path, port: int) -> Any:
    import uvicorn

    from aibom.server.app import create_app, get_cloner

    @contextlib.contextmanager
    def fake_clone(_url: str, *, ref: str | None = None) -> Iterator[Path]:
        # A throwaway copy, as the real cloner would give: the scan can never
        # touch the fixture in the working tree.
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / fixture.name
            shutil.copytree(fixture, dest)
            yield dest

    app = create_app()
    app.dependency_overrides[get_cloner] = lambda: fake_clone
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("server did not start")
        time.sleep(0.05)
    return server


DEMOS = "demos"
# (name, page, button that starts it, dependency-map host, legend, detail panel)
_DEMO_CASES = (
    ("sample", "/", "#runDemo", "graph", "edgeLegend", "graphDetail"),
    ("privilege-drift", "/#compare", "#driftDemoPolicy", "driftDepGraph", "driftDepLegend",
     "driftDepDetail"),
    ("mcp-tool-exposure", "/#compare", "#driftDemoMcp", "driftDepGraph", "driftDepLegend",
     "driftDepDetail"),
    ("compare", "/#compare", "#compareDemoPy", "compareDepGraph", "compareDepLegend",
     "compareDepDetail"),
)
#: Narrow phone and desktop widths from the review's acceptance criteria.
_VIEWPORTS = (403, 1280)
#: Smallest rendered map label height, in CSS pixels, that still reads.
_MIN_LABEL_PX = 9.0


def _viewport_checks(
    page: Any, port: int, width: int, out: Path
) -> tuple[dict[str, Any], list[str]]:
    """Load the sample at ``width`` and measure what a reader can actually reach."""
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"http://127.0.0.1:{port}/")
    page.locator("#runDemo").click()
    page.wait_for_selector("#securitySummary .headline", timeout=60_000)
    checks: dict[str, Any] = page.evaluate(
        """(w) => {
          const tabs = [...document.querySelectorAll('.result-tab')].filter(t => !t.hidden);
          return {
            page_overflow_px: document.documentElement.scrollWidth - window.innerWidth,
            tabs: tabs.length,
            tabs_off_screen: tabs.filter(t => {
              const r = t.getBoundingClientRect(); return r.right > w + 1 || r.left < -1;
            }).map(t => t.dataset.tab),
            headline: document.querySelector('#securitySummary .headline-label').textContent,
            body_font_px: parseFloat(getComputedStyle(document.body).fontSize),
          };
        }""",
        width,
    )
    page.screenshot(path=str(out / f"ui-{DEMOS}-viewport-{width}.png"), full_page=True)
    page.locator('[data-tab="graph"]').click()
    page.wait_for_selector("#graph svg", timeout=60_000)
    checks["min_label_px"] = page.evaluate(
        "() => Math.min(...[...document.querySelectorAll('#graph .node text')]"
        ".map(t => t.getBoundingClientRect().height))"
    )
    page.locator("#graphSection").screenshot(path=str(out / f"ui-{DEMOS}-viewport-{width}-map.png"))
    failures = []
    prefix = f"viewport {width}px: "
    if checks["page_overflow_px"] > 0:
        failures.append(prefix + f"page scrolls sideways by {checks['page_overflow_px']}px")
    if checks["tabs_off_screen"]:
        failures.append(prefix + f"tabs off screen: {checks['tabs_off_screen']}")
    if checks["min_label_px"] < _MIN_LABEL_PX:
        failures.append(prefix + f"map labels {checks['min_label_px']:.1f}px < {_MIN_LABEL_PX}px")
    if checks["body_font_px"] < 15:
        failures.append(prefix + "body text below 15px")
    if checks["headline"] != "Action required":
        failures.append(prefix + "sample with a critical finding is not headed 'Action required'")
    return checks, failures


#: Appended to every repository-controlled string: closes an attribute and a
#: tag, then adds an element the check can count.
_INJECTION = "\"'><img src=x onerror=\"window.__xss=1\"><b data-pwned=1>"
#: Enum-like fields the UI switches on. Every other string (names, labels,
#: files, versions, ids) can come from a scanned repository.
_ENUM_KEYS = frozenset({
    "severity", "type", "status", "role", "kind", "verdict", "state", "relations",
    "scope", "category", "source_kind", "sink_kind", "trust_boundary", "evidence_level",
    "usage", "change_type", "bomFormat", "specVersion", "edge_type", "reachable",
    "strength", "privileged", "impact", "confidence_level", "lifecycle", "match",
    "severity_rule", "operation_class", "effect", "decision", "mode", "level",
})


def _taint(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {k: _taint(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_taint(v, key) for v in value]
    if isinstance(value, str) and key not in _ENUM_KEYS and not value.startswith("http"):
        return value + _INJECTION
    return value


def _dependency_graph_checks(page: Any, port: int, out: Path) -> tuple[dict[str, Any], list[str]]:
    """The sample's package graph matches the API's dependency table, edge for edge."""
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto(f"http://127.0.0.1:{port}/")
    with page.expect_response(lambda r: r.url.endswith("/api/demo")) as response:
        page.locator("#runDemo").click()
    summary = response.value.json()["dependencies"]["summary"]
    page.wait_for_selector("#securitySummary .headline", timeout=60_000)
    page.locator('[data-tab="deps"]').click()
    page.wait_for_selector("#depsGraph svg", timeout=60_000)
    checks: dict[str, Any] = page.evaluate(
        """() => ({
          nodes: document.querySelectorAll('#depsGraph .node').length,
          edges: document.querySelectorAll('#depsGraph line.edge').length,
          edges_citing_lockfile: [...document.querySelectorAll('#depsGraph line.edge title')]
            .filter(t => /\.lock:\d+\)$/.test(t.textContent)).length,
          left_to_right: [...document.querySelectorAll('#depsGraph line.edge')]
            .every(l => +l.getAttribute('x2') > +l.getAttribute('x1')),
        })"""
    )
    page.locator("#depsSection").screenshot(path=str(out / f"ui-{DEMOS}-dependency-graph.png"))
    page.locator("#depsGraph .node circle").first.dispatch_event("click")
    checks["detail"] = page.locator("#depsDetail").inner_text()
    checks["api"] = {"total": summary["total"], "edges": summary["edges"]}
    failures = []
    if checks["nodes"] != summary["total"] or checks["edges"] != summary["edges"]:
        failures.append(f"dependency graph: drew {checks['nodes']} nodes / {checks['edges']} "
                        f"edges, API has {summary['total']} / {summary['edges']}")
    if checks["edges_citing_lockfile"] != checks["edges"]:
        failures.append("dependency graph: an edge does not cite its lockfile line")
    if not checks["left_to_right"]:
        failures.append("dependency graph: an arrow points backwards (layering broke)")
    if ".lock:" not in checks["detail"]:
        failures.append("dependency graph: the detail panel shows no lockfile evidence")
    return checks, failures


def _injection_checks(page: Any, port: int) -> tuple[dict[str, Any], list[str]]:
    """Render every demo view from tainted API data; nothing may become markup."""

    def tainted(route: Any) -> None:
        response = route.fetch()
        route.fulfill(response=response, json=_taint(response.json()))

    patterns = ("**/api/demo", "**/api/diff/demo*", "**/api/agent-drift/demo*")
    for pattern in patterns:
        page.route(pattern, tainted)
    count = "() => [window.__xss || 0, document.querySelectorAll('[data-pwned]').length]"
    checks: dict[str, Any] = {}
    page.set_viewport_size({"width": 1400, "height": 1000})
    page.goto(f"http://127.0.0.1:{port}/")
    page.locator("#runDemo").click()
    page.wait_for_selector("#securitySummary .headline", timeout=60_000)
    for tab in page.locator(".result-tab:visible").all():
        tab.click()
        if tab.get_attribute("data-tab") == "graph":
            page.wait_for_selector("#graph svg", timeout=60_000)
            # Opens the detail panel, which renders names and evidence too.
            page.locator("#graph .node circle").first.dispatch_event("click")
    checks["sample"] = page.evaluate(count)
    for button in ("#compareDemoPy", "#driftDemoPolicy", "#driftDemoMcp"):
        page.goto(f"http://127.0.0.1:{port}/#compare")
        page.locator(button).click()
        page.wait_for_selector("#compareResult:not([hidden]), #privResult:not([hidden])",
                               timeout=60_000)
        nodes = page.locator(".path-node")
        if nodes.count():
            nodes.first.dispatch_event("click")
        checks[button.lstrip("#")] = page.evaluate(count)
    for pattern in patterns:
        page.unroute(pattern)
    failures = [f"injection: {view} rendered repository data as markup {found}"
                for view, found in checks.items() if any(found)]
    return checks, failures


def _graph_checks(page: Any, host: str, legend: str, detail: str) -> dict[str, Any]:
    """Count nodes/edges/arrows in one graph and read the best-connected node's panel."""
    checks: dict[str, Any] = {
        "nodes": page.locator(f"#{host} .node").count(),
        "edges": page.locator(f"#{host} line.edge").count(),
        "edges_with_arrow": page.locator(f"#{host} line.edge[marker-end]").count(),
        "edges_with_evidence": page.evaluate(
            "(h) => (document.getElementById(h)._links || [])"
            ".filter(l => l.evidence && l.evidence.length).length",
            host,
        ),
    }
    checks["edge_legend"] = page.locator(f"#{legend}").inner_text() if checks["edges"] else ""
    best = page.evaluate(
        """(h) => {
          const host = document.getElementById(h);
          const nodes = host._nodes || [];
          const links = host._links || [];
          let best = -1, score = -1;
          nodes.forEach((n, i) => {
            const s = links.filter(l => l.s.id === n.id || l.t.id === n.id).length;
            if (s > score) { score = s; best = i; }
          });
          return best;
        }""",
        host,
    )
    if best >= 0:
        page.locator(f"#{host} .node").nth(best).locator("circle").click()
        checks["detail_panel"] = page.locator(f"#{detail}").inner_text()
    return checks


def _graph_failures(checks: dict[str, Any], prefix: str = "") -> list[str]:
    failures = []
    if checks.get("nodes", 0) == 0:
        failures.append(prefix + "graph rendered no nodes")
    if checks.get("edges", 0) != checks.get("edges_with_arrow", -1):
        failures.append(prefix + "some edges have no direction marker")
    if checks.get("edges", 0) and not checks.get("edge_legend"):
        failures.append(prefix + "edges drawn without an edge-type legend")
    if "Connections" not in checks.get("detail_panel", "Connections"):
        failures.append(prefix + "detail panel does not list connections")
    return failures


def run_demos(out: Path) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("BLOCKED: playwright is not installed", file=sys.stderr)
        return BLOCKED
    out.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    server = _serve(FIXTURES / "vulnerable-ai-app", port)  # demos never clone
    report: dict[str, Any] = {"fixture": DEMOS, "checks": {}, "console_errors": []}
    failures: list[str] = []
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # noqa: BLE001 - any launch failure is BLOCKED
                print(f"BLOCKED: chromium unavailable: {exc}", file=sys.stderr)
                return BLOCKED
            page = browser.new_page(viewport={"width": 1400, "height": 1000})
            page.on(
                "console",
                lambda msg: report["console_errors"].append(msg.text)
                if msg.type == "error"
                else None,
            )
            page.on("pageerror", lambda err: report["console_errors"].append(str(err)))
            for name, path, button, host, legend, detail in _DEMO_CASES:
                page.goto(f"http://127.0.0.1:{port}{path}")
                page.locator(button).click()
                if host == "graph":
                    page.locator('[data-tab="graph"]').click(timeout=60_000)
                page.wait_for_selector(f"#{host} svg, #{host} p", timeout=60_000)
                checks = _graph_checks(page, host, legend, detail)
                # Demo edges are all evidence-backed; an unlabelled one is a bug.
                if checks["edges_with_evidence"] != checks["edges"]:
                    failures.append(f"{name}: some edges carry no evidence")
                if checks["edges"] == 0:
                    failures.append(f"{name}: dependency map has no edges")
                failures += _graph_failures(checks, f"{name}: ")
                report["checks"][name] = checks
                page.locator(f"#{host}").locator("xpath=ancestor::div[contains(@class,"
                                                 "'graphgrid')]").screenshot(
                    path=str(out / f"ui-{DEMOS}-{name}.png")
                )
            for width in _VIEWPORTS:
                checks, problems = _viewport_checks(page, port, width, out)
                report["checks"][f"viewport-{width}"] = checks
                failures += problems
            checks, problems = _dependency_graph_checks(page, port, out)
            report["checks"]["dependency-graph"] = checks
            failures += problems
            checks, problems = _injection_checks(page, port)
            report["checks"]["injection"] = checks
            failures += problems
            browser.close()
    finally:
        server.should_exit = True
    if report["console_errors"]:
        failures.append("browser console errors")
    report["failures"] = failures
    report["status"] = "FAIL" if failures else "PASS"
    (out / f"ui-{DEMOS}.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    summary = {k: {"nodes": v["nodes"], "edges": v["edges"]} if "nodes" in v else v
               for k, v in report["checks"].items()}
    print(json.dumps({"fixture": DEMOS, "status": report["status"], **summary,
                      "failures": failures}))  # ASCII: Windows consoles are cp932
    return FAIL if failures else PASS


def run(fixture_name: str, out: Path) -> int:
    if fixture_name == DEMOS:
        return run_demos(out)
    fixture = FIXTURES / fixture_name
    if not fixture.is_dir():
        print(f"FAIL: no fixture {fixture}", file=sys.stderr)
        return FAIL
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("BLOCKED: playwright is not installed", file=sys.stderr)
        return BLOCKED

    out.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    server = _serve(fixture, port)
    report: dict[str, Any] = {"fixture": fixture_name, "checks": {}, "console_errors": []}
    status = PASS
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # noqa: BLE001 - any launch failure is BLOCKED
                print(f"BLOCKED: chromium unavailable: {exc}", file=sys.stderr)
                return BLOCKED
            page = browser.new_page(viewport={"width": 1400, "height": 1000})
            page.on(
                "console",
                lambda msg: report["console_errors"].append(msg.text)
                if msg.type == "error"
                else None,
            )
            page.on("pageerror", lambda err: report["console_errors"].append(str(err)))

            def static_only(route: Any) -> None:
                # The UI asks for network enrichment; the check must stay offline.
                body = json.loads(route.request.post_data or "{}")
                body.update(resolve=False, vulns=False)
                route.continue_(post_data=json.dumps(body))

            # Both the stream and the plain fallback: never let either go online.
            page.route("**/api/scan", static_only)
            page.route("**/api/scan/stream", static_only)
            streamed: list[Any] = []
            page.on("response", lambda r: streamed.append(r)
                    if r.url.endswith("/api/scan/stream") else None)
            repo = f"https://github.com/example/{fixture_name}"
            page.goto(f"http://127.0.0.1:{port}/?repo={repo}")
            page.locator('[data-tab="graph"]').click(timeout=60_000)
            page.wait_for_selector("#graph svg, #graph p", timeout=60_000)

            report["checks"].update(_graph_checks(page, "graph", "edgeLegend", "graphDetail"))
            lines = [json.loads(line) for r in streamed for line in r.text().splitlines()
                     if line.strip()]
            report["checks"]["stream_stages"] = [ln["stage"] for ln in lines if "stage" in ln]
            report["checks"]["stream_result"] = any("result" in ln for ln in lines)
            report["checks"]["status_text"] = page.locator("#status").text_content()
            page.locator("#graphSection").screenshot(path=str(out / f"ui-{fixture_name}.png"))
            browser.close()
    finally:
        server.should_exit = True

    checks = report["checks"]
    failures = _graph_failures(checks)
    stages = checks.get("stream_stages", [])
    if not checks.get("stream_result") or stages[:2] != ["clone", "collect"] \
            or stages[-1:] != ["report"]:
        failures.append(f"scan did not stream its stages and result: {stages}")
    if "resolve" in stages or "vulns" in stages:
        failures.append("the offline check reached a network stage (resolve/vulns)")
    if report["console_errors"]:
        failures.append("browser console errors")
    report["failures"] = failures
    if failures:
        status = FAIL
    report["status"] = {PASS: "PASS", FAIL: "FAIL"}[status]
    (out / f"ui-{fixture_name}.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({"fixture": fixture_name, "status": report["status"], **checks,
                      "failures": failures}))  # ASCII: Windows consoles are cp932
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--fixture", default="vulnerable-ai-app")
    parser.add_argument("--out", type=Path, default=ROOT / "verify-out")
    args = parser.parse_args()
    return run(args.fixture, args.out)


if __name__ == "__main__":
    sys.exit(main())
