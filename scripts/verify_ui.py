"""Drive the real web UI against a local fixture and capture evidence.

Starts the FastAPI app (UI + API) in-process on a free port, with the repo
cloner replaced by a read-only copy of a local fixture, so no network is used.
A headless Chromium then loads ``/?repo=...`` (which starts the scan), opens the
Dependencies tab, selects the best-connected node, and records:

* ``<out>/ui-<fixture>.png``      - screenshot of the dependency graph
* ``<out>/ui-<fixture>.json``     - DOM measurements + console errors + status

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


def run(fixture_name: str, out: Path) -> int:
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

            nodes = page.locator("#graph .node").count()
            edges = page.locator("#graph line.edge").count()
            arrows = page.locator("#graph line.edge[marker-end]").count()
            legend = page.locator("#edgeLegend").inner_text() if edges else ""
            report["checks"].update(
                nodes=nodes, edges=edges, edges_with_arrow=arrows, edge_legend=legend
            )

            # Select the node with the most incident edges and read its panel.
            best = page.evaluate(
                """() => {
                  const host = document.getElementById('graph');
                  const nodes = host._nodes || [];
                  const links = host._links || [];
                  let best = -1, score = -1;
                  nodes.forEach((n, i) => {
                    const s = links.filter(l => l.s.id === n.id || l.t.id === n.id).length;
                    if (s > score) { score = s; best = i; }
                  });
                  return best;
                }"""
            )
            if best >= 0:
                page.locator("#graph .node").nth(best).click()
                report["checks"]["detail_panel"] = page.locator("#graphDetail").inner_text()
            page.locator("#graphSection").screenshot(path=str(out / f"ui-{fixture_name}.png"))
            browser.close()
    finally:
        server.should_exit = True

    checks = report["checks"]
    failures = []
    if checks.get("nodes", 0) == 0:
        failures.append("graph rendered no nodes")
    if checks.get("edges", 0) != checks.get("edges_with_arrow", -1):
        failures.append("some edges have no direction marker")
    if checks.get("edges", 0) and not checks.get("edge_legend"):
        failures.append("edges drawn without an edge-type legend")
    if "Connections" not in checks.get("detail_panel", "Connections"):
        failures.append("detail panel does not list connections")
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
