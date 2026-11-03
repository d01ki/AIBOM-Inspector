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
(``<out>/ui-demos-<demo>.png`` and ``<out>/ui-demos.json``).

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
# (name, button that starts it, dependency-map host, legend, detail panel)
_DEMO_CASES = (
    ("sample", "#runDemo", "graph", "edgeLegend", "graphDetail"),
    ("privilege-drift", "#heroDrift", "driftDepGraph", "driftDepLegend", "driftDepDetail"),
    ("mcp-tool-exposure", "#heroMcp", "driftDepGraph", "driftDepLegend", "driftDepDetail"),
    ("compare", "#compareDemoPy", "compareDepGraph", "compareDepLegend", "compareDepDetail"),
)


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
        page.locator(f"#{host} .node").nth(best).click()
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
            for name, button, host, legend, detail in _DEMO_CASES:
                page.goto(f"http://127.0.0.1:{port}/")
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
    summary = {k: {"nodes": v["nodes"], "edges": v["edges"]} for k, v in report["checks"].items()}
    print(json.dumps({"fixture": DEMOS, "status": report["status"], **summary,
                      "failures": failures}, ensure_ascii=False))
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

            page.route("**/api/scan", static_only)
            repo = f"https://github.com/example/{fixture_name}"
            page.goto(f"http://127.0.0.1:{port}/?repo={repo}")
            page.locator('[data-tab="graph"]').click(timeout=60_000)
            page.wait_for_selector("#graph svg, #graph p", timeout=60_000)

            report["checks"].update(_graph_checks(page, "graph", "edgeLegend", "graphDetail"))
            page.locator("#graphSection").screenshot(path=str(out / f"ui-{fixture_name}.png"))
            browser.close()
    finally:
        server.should_exit = True

    checks = report["checks"]
    failures = _graph_failures(checks)
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
                      "failures": failures}, ensure_ascii=False))
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--fixture", default="vulnerable-ai-app")
    parser.add_argument("--out", type=Path, default=ROOT / "verify-out")
    args = parser.parse_args()
    return run(args.fixture, args.out)


if __name__ == "__main__":
    sys.exit(main())
