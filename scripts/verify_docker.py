"""Verify the image the way people run it: local Docker, the CLI inside the
container, Compose, and a Cloud Run-shaped container (PORT=8080, 1 vCPU,
1 GiB, read-only root filesystem, the deploy script's environment, SIGTERM).

usage: python scripts/verify_docker.py [out_dir] [--no-browser]   (from the repo root)

Each check prints PASS, FAIL or BLOCKED with its evidence; the full record is
written to ``<out_dir>/docker-verify.json`` (default ``verify-out/docker``).
Exit 1 if any check failed. The browser check needs Playwright (CI installs
it; it is not a project dependency). Without Playwright that check is
BLOCKED, never PASS; ``--no-browser`` skips it. Needs Docker; sends nothing
anywhere (only the bundled offline demos are scanned).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
NO_BROWSER = "--no-browser" in sys.argv
OUT = Path(ARGS[0] if ARGS else "verify-out/docker").resolve()
IMAGE = "aibom-inspector:verify"
REPO = Path.cwd()
# What the bundled sample must show; the same numbers as a source checkout,
# so a wheel that dropped the demo's uv.lock fails here.
DEMO_PACKAGES, DEMO_EDGES = 44, 77
results: list[dict[str, Any]] = []


def record(name: str, ok: bool | None, evidence: Any) -> None:
    """``ok=None`` is BLOCKED: the check could not run on this machine."""
    status = "BLOCKED" if ok is None else "PASS" if ok else "FAIL"
    results.append({"check": name, "status": status, "evidence": evidence})
    print(f"{status:7}  {name}: {json.dumps(evidence)[:300]}", flush=True)


def sh(*cmd: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd), capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )


def http(
    method: str, url: str, *, timeout: int = 180, headers: dict[str, str] | None = None
) -> tuple[int, bytes, dict[str, str]]:
    data = b"" if method == "POST" else None
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {k.lower(): v for k, v in exc.headers.items()}


def wait_health(base: str, seconds: int = 60) -> float | None:
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        try:
            if http("GET", f"{base}/api/health", timeout=3)[0] == 200:
                return round(time.monotonic() - start, 2)
        except OSError:
            pass
        time.sleep(0.5)
    return None


def api_checks(prefix: str, base: str) -> None:
    status, body, _ = http("GET", f"{base}/api/health")
    record(f"{prefix}: GET /api/health", status == 200 and b'"ok"' in body, body.decode()[:120])

    status, body, headers = http("GET", f"{base}/")
    record(
        f"{prefix}: GET / serves the UI with a CSP",
        status == 200 and b"<html" in body.lower() and "content-security-policy" in headers,
        {"status": status, "bytes": len(body)},
    )
    status, body, _ = http("GET", f"{base}/app.js")
    record(f"{prefix}: GET /app.js", status == 200 and len(body) > 10_000, {"bytes": len(body)})

    started = time.monotonic()
    status, body, _ = http("POST", f"{base}/api/demo")
    data = json.loads(body) if status == 200 else {}
    summary = data.get("dependencies", {}).get("summary", {})
    record(
        f"{prefix}: POST /api/demo (bundled sample, offline)",
        status == 200
        and summary.get("total") == DEMO_PACKAGES
        and summary.get("edges") == DEMO_EDGES
        and bool(data.get("cyclonedx", {}).get("components")),
        {
            "status": status,
            "seconds": round(time.monotonic() - started, 2),
            "counts": data.get("counts"),
            "dependency_summary": summary,
        },
    )
    for path in (
        "/api/agent-drift/demo",
        "/api/agent-drift/demo?scenario=mcp-tool-exposure",
        "/api/diff/demo",
    ):
        status, body, _ = http("POST", f"{base}{path}")
        record(f"{prefix}: POST {path}", status == 200 and len(body) > 1000,
               {"status": status, "bytes": len(body)})
    status, body, _ = http("POST", f"{base}/api/demo/sarif")
    sarif = json.loads(body) if status == 200 else {}
    runs = sarif.get("runs") or [{}]
    record(f"{prefix}: POST /api/demo/sarif", sarif.get("version") == "2.1.0",
           {"status": status, "results": len(runs[0].get("results", []))})


def browser_check(prefix: str, base: str) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        record(f"{prefix}: browser renders the sample", None, "playwright is not installed")
        return
    errors: list[str] = []
    shot = OUT / f"{prefix}-sample.png"
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"{base}/")
        page.locator("#runDemo").click()
        page.wait_for_selector("#securitySummary .headline", timeout=60_000)
        page.wait_for_selector("#depsGraph svg", timeout=60_000)
        nodes = page.locator("#depsGraph .node").count()
        headline = page.locator("#securitySummary .headline").inner_text()[:160]
        page.screenshot(path=str(shot), full_page=True)
        browser.close()
    record(f"{prefix}: browser renders the sample", nodes > 0 and not errors,
           {"dependency_nodes": nodes, "console_errors": errors[:3], "headline": headline,
            "screenshot": str(shot)})


def start(name: str, *args: str) -> bool:
    sh("docker", "rm", "-f", name)
    proc = sh("docker", "run", "-d", "--name", name, *args, IMAGE)
    if proc.returncode:
        record(f"{name}: container starts", False, proc.stderr[-300:])
    return proc.returncode == 0


def stop(prefix: str, name: str) -> None:
    started = time.monotonic()
    sh("docker", "stop", "-t", "10", name)
    took = round(time.monotonic() - started, 2)
    state = json.loads(sh("docker", "inspect", name).stdout)[0]["State"]
    logs = sh("docker", "logs", name)
    text = logs.stdout + logs.stderr
    (OUT / f"{name}.log").write_text(text, encoding="utf-8")
    graceful = "Finished server process" in text
    record(f"{prefix}: SIGTERM stops uvicorn gracefully", graceful and took < 9,
           {"stop_seconds": took, "exit_code": state["ExitCode"], "graceful_log": graceful})
    sh("docker", "rm", "-f", name)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # 1. build ---------------------------------------------------------------
    started = time.monotonic()
    build = sh("docker", "build", "-t", IMAGE, ".", timeout=1800)
    (OUT / "build.log").write_text(build.stdout + build.stderr, encoding="utf-8")
    record("docker build", build.returncode == 0,
           {"seconds": round(time.monotonic() - started, 1), "tail": build.stderr[-200:]})
    if build.returncode:
        return 1
    started = time.monotonic()
    rebuild = sh("docker", "build", "-q", "-t", IMAGE, ".")
    record("an unchanged rebuild is a cache hit (the launchers rebuild every run)",
           rebuild.returncode == 0 and time.monotonic() - started < 20,
           {"seconds": round(time.monotonic() - started, 1)})
    config = json.loads(sh("docker", "image", "inspect", IMAGE).stdout)[0]
    record("image: non-root user and a healthcheck",
           config["Config"]["User"] == "aibom" and bool(config["Config"].get("Healthcheck")),
           {"user": config["Config"]["User"], "size_mb": round(config["Size"] / 1e6)})

    # 2. local docker run, the `./aibom ui` shape ---------------------------
    if start("aibom-verify-local", "-p", "18000:8000", "-e", "AIBOM_PORT=18000"):
        base = "http://127.0.0.1:18000"
        record("local: server ready", (ready := wait_health(base)) is not None,
               {"seconds": ready})
        api_checks("local", base)
        if not NO_BROWSER:
            browser_check("local", base)
        deadline = time.monotonic() + 45
        health = ""
        while time.monotonic() < deadline and '"healthy"' not in health:
            health = sh("docker", "inspect", "--format", "{{json .State.Health.Status}}",
                        "aibom-verify-local").stdout.strip()
            time.sleep(2)
        record("local: Docker HEALTHCHECK reports healthy", health == '"healthy"', health)
        stop("local", "aibom-verify-local")

    # 3. the CLI in the container, the `./aibom scan` shape ------------------
    cli_out = OUT / "cli-out"
    cli_out.mkdir(exist_ok=True)
    fixture = REPO / "tests" / "fixtures" / "locked-js-app"
    # As the ./aibom launcher runs it: the host user on Linux and macOS, so the
    # container can write the host-owned output directory.
    user = (
        ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]
        if hasattr(os, "getuid")
        else []
    )
    proc = sh("docker", "run", "--rm", *user, "-v", f"{fixture}:/work:ro",
              "-v", f"{cli_out}:/out", "-w", "/work", IMAGE, "aibom", "scan", "/work", "-q",
              "-o", "/out/inv.json", "-c", "/out/bom.json", "--sarif", "/out/findings.sarif",
              "-r", "/out/report.html")
    files = {p.name: p.stat().st_size for p in cli_out.iterdir()}
    inv_path = cli_out / "inv.json"
    inv = json.loads(inv_path.read_text(encoding="utf-8")) if inv_path.is_file() else {}
    wanted = {"inv.json", "bom.json", "findings.sarif", "report.html"}
    record("cli: scan a read-only mount and write artifacts to /out",
           proc.returncode == 0 and wanted <= set(files),
           {"exit": proc.returncode, "files": files, "stderr": proc.stderr[-300:],
            "stdout": proc.stdout[-300:],
            "packages": sum(1 for e in inv.get("entities", []) if e["type"] == "package")})
    proc = sh("docker", "run", "--rm", IMAGE, "aibom", "demo")
    record("cli: aibom demo runs offline", proc.returncode in (0, 1) and len(proc.stdout) > 200,
           {"exit": proc.returncode, "stdout_tail": proc.stdout[-160:]})
    proc = sh("docker", "run", "--rm", IMAGE, "aibom", "scan", "/does-not-exist")
    record("cli: a missing target exits 2 without a traceback",
           proc.returncode == 2 and "Traceback" not in proc.stderr,
           {"exit": proc.returncode, "stderr": proc.stderr[-160:]})

    # 4. Cloud Run shape (scripts/deploy-cloud-run.sh settings) ---------------
    env = [
        "PORT=8080",
        "AIBOM_CORS_ORIGINS=https://aibom-inspector.com,https://www.aibom-inspector.com",
        "AIBOM_MAX_CLONE_MB=100",
        "AIBOM_MAX_CLONE_FILES=15000",
    ]
    args = ["-p", "18080:8080", "--cpus", "1", "--memory", "1g", "--read-only",
            "--tmpfs", "/tmp:rw,size=512m"]
    for item in env:
        args += ["-e", item]
    if start("aibom-verify-cloudrun", *args):
        base = "http://127.0.0.1:18080"
        record("cloud-run: ready on $PORT=8080 (read-only root fs, 1 vCPU, 1 GiB)",
               (ready := wait_health(base)) is not None, {"seconds": ready})
        api_checks("cloud-run", base)
        _, _, headers = http("GET", f"{base}/api/health",
                             headers={"Origin": "https://evil.example"})
        allowed = headers.get("access-control-allow-origin")
        record("cloud-run: CORS refuses a foreign origin", allowed is None,
               {"allow_origin": allowed})
        _, _, headers = http("GET", f"{base}/api/health",
                             headers={"Origin": "https://aibom-inspector.com"})
        record("cloud-run: CORS allows the site's own origin",
               headers.get("access-control-allow-origin") == "https://aibom-inspector.com",
               {"allow_origin": headers.get("access-control-allow-origin")})
        mem = sh("docker", "stats", "--no-stream", "--format", "{{.MemPerc}}",
                 "aibom-verify-cloudrun").stdout.strip()
        record("cloud-run: memory after the demos is well under 1 GiB",
               bool(mem) and float(mem.rstrip("%") or 100) < 80, mem)
        stop("cloud-run", "aibom-verify-cloudrun")

    # 5. compose --------------------------------------------------------------
    cfg = sh("docker", "compose", "config", "-q")
    record("compose: docker-compose.yml is valid", cfg.returncode == 0, cfg.stderr[-200:])

    (OUT / "docker-verify.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    failed = sum(r["status"] == "FAIL" for r in results)
    blocked = sum(r["status"] == "BLOCKED" for r in results)
    print(f"\n{len(results) - failed - blocked} PASS, {failed} FAIL, {blocked} BLOCKED;"
          f" evidence in {OUT}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
