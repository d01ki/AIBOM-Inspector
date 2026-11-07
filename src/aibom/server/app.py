"""FastAPI application: scan a public repo URL and return an AIBOM + risk report."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractContextManager, asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from aibom import __version__
from aibom.agent_security.analyzer import analyze as analyze_agents
from aibom.agent_security.drift import compare_reports as compare_privileges
from aibom.agent_security.models import AgentSecurityReport
from aibom.agent_security.safeio import InputError
from aibom.agent_security.scenario import SCENARIOS, run_scenario, scenario_root
from aibom.compliance.minimum_elements import evaluate_cyclonedx
from aibom.demo import (
    crossfile_drift_demo_paths,
    drift_demo_paths,
    impact_demo_path,
    ts_drift_demo_paths,
)
from aibom.drift import compare_scan_results
from aibom.export.cyclonedx import to_cyclonedx
from aibom.export.sarif import to_sarif
from aibom.graph import build_dependency_list, build_graph
from aibom.impact import build_impact_paths, build_unresolved_impacts
from aibom.policy import production_ai_component_count, production_view
from aibom.report.html import coverage_notes, render_html
from aibom.risk.scoring import headline
from aibom.server.clone import CloneError, clone_repo, normalize_repo_url
from aibom.service import ScanResult, run_scan
from aibom.vuln.osv import group_by_package

# A cloner takes a URL (and optional git ref) and returns a context manager
# yielding the checkout path.
Cloner = Callable[..., AbstractContextManager[Path]]
# Called with a stage id as each scan step starts; raising stops the scan.
Progress = Callable[[str], None]

log = logging.getLogger(__name__)


class ScanCancelled(Exception):
    """The client went away; the scan stops at the next stage boundary."""


class ScanRequest(BaseModel):
    """Body for ``POST /api/scan`` and ``/api/report``.

    The backend has network by definition (it just cloned the repo), so
    enrichment — HF metadata resolution and OSV vulnerability mapping —
    defaults to on; pass ``resolve: false`` for a purely static scan.
    """

    repo_url: str = Field(description="Public repo URL, e.g. https://github.com/owner/repo")
    ref: str | None = Field(
        default=None, description="Branch, tag, or commit SHA; the default branch if omitted."
    )
    resolve: bool = Field(
        default=True, description="Enrich HF models/datasets (license, model card, formats)."
    )
    vulns: bool = Field(
        default=True, description="Map pinned dependencies to known vulnerabilities (OSV)."
    )
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class DiffRequest(BaseModel):
    """Body for ``POST /api/diff`` — one repository at two revisions.

    This is the web equivalent of ``aibom diff``: it answers whether a revision
    introduced a new untrusted-to-privileged path, even when the component
    inventory is byte-for-byte identical.
    """

    repo_url: str = Field(description="Public repo URL, e.g. https://github.com/owner/repo")
    base_ref: str = Field(description="Baseline branch, tag, or commit SHA.")
    head_ref: str = Field(description="Candidate branch, tag, or commit SHA.")
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


def get_cloner() -> Cloner:
    """Dependency: the real clone implementation (overridden in tests)."""
    return clone_repo


def _cors_origins() -> list[str]:
    raw = os.environ.get("AIBOM_CORS_ORIGINS", "*").strip()
    return [o.strip() for o in raw.split(",") if o.strip()] or ["*"]


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Tell the human where to point their browser once the app is up.

    ``AIBOM_PORT`` (set by docker-compose to the *host*-side port) wins over
    ``PORT`` (the in-container bind port) so the printed URL is the one that
    actually works from the user's machine.
    """
    port = os.environ.get("AIBOM_PORT") or os.environ.get("PORT") or "8000"
    print(
        f"\n  AIBOM Inspector is ready -- open  http://localhost:{port}  in your browser\n"
        "  Quick demo: click \"Try the bundled sample\" (no URL or network needed)\n"
        "  CLI demo:   docker compose run --rm demo\n"
        f"  (from another machine: http://<this-host's-IP>:{port})\n",
        flush=True,
    )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIBOM Inspector API",
        version=__version__,
        summary="Discover, inventory, and risk-analyze AI supply chains from a repo URL.",
        lifespan=_lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/api/scan")
    def scan(
        req: ScanRequest, cloner: Annotated[Cloner, Depends(get_cloner)]
    ) -> dict[str, Any]:
        result, agents = _scan_with_agents(req, cloner)
        return _to_payload(req.repo_url, result, agents)

    @app.post("/api/scan/stream")
    async def scan_stream(
        req: ScanRequest, cloner: Annotated[Cloner, Depends(get_cloner)]
    ) -> StreamingResponse:
        """``/api/scan`` as NDJSON: one ``{"stage": id}`` line per step, then
        ``{"result": payload}`` or ``{"error": detail, "status": code}``.

        Disconnecting cancels the work at the next stage boundary.
        """
        _validated_url(req.repo_url)  # a bad URL is a plain 400, before streaming
        return StreamingResponse(
            _stream_scan(req, cloner), media_type="application/x-ndjson"
        )

    @app.post("/api/demo")
    def demo_scan() -> dict[str, Any]:
        result = _run_demo()
        path = impact_demo_path()
        agents = _agent_payload(path, result, "built-in://impact-demo") if path else None
        return _to_payload("built-in://impact-demo", result, agents)

    @app.post("/api/agent-drift/demo")
    def agent_drift_demo(scenario: str = "agent-privilege-drift") -> dict[str, Any]:
        """Offline Baseline -> Candidate -> Fixed privilege drift, as ``aibom demo --scenario``."""
        meta = SCENARIOS.get(scenario)
        if meta is None:
            raise HTTPException(
                status_code=400, detail=f"scenario must be one of: {', '.join(SCENARIOS)}"
            )
        root = scenario_root(scenario)
        if root is None:
            raise HTTPException(
                status_code=503, detail=f"the built-in {scenario} scenario is unavailable"
            )
        outcome = run_scenario(root, scenario)
        return {
            "scenario": {
                "name": meta.name,
                "changed": meta.changed,
                "change": meta.change,
                "fix": meta.fix,
            },
            "revisions": {
                stage: _revision_summary(scan) for stage, scan in outcome.scans.items()
            },
            "reports": {
                stage: report.model_dump(mode="json") for stage, report in outcome.reports.items()
            },
            "introduced": outcome.introduced.model_dump(mode="json"),
            "fixed": outcome.fixed.model_dump(mode="json"),
            "residual": outcome.residual.model_dump(mode="json"),
        }

    @app.post("/api/report", response_class=HTMLResponse)
    def report(
        req: ScanRequest, cloner: Annotated[Cloner, Depends(get_cloner)]
    ) -> HTMLResponse:
        result = _scan(req, cloner)
        html = render_html(result.inventory, result.findings, result.score)
        return HTMLResponse(content=html)

    @app.post("/api/demo/report", response_class=HTMLResponse)
    def demo_report() -> HTMLResponse:
        result = _run_demo()
        return HTMLResponse(
            content=render_html(result.inventory, result.findings, result.score)
        )

    @app.post("/api/diff")
    def diff(
        req: DiffRequest, cloner: Annotated[Cloner, Depends(get_cloner)]
    ) -> dict[str, Any]:
        display = _validated_url(req.repo_url)
        try:
            with cloner(req.repo_url, ref=req.base_ref) as base_path:
                baseline = run_scan(
                    base_path,
                    min_confidence=req.min_confidence,
                    display_target=f"{display}@{req.base_ref}",
                    ref=req.base_ref,
                )
                base_agents = _agent_report(base_path, baseline, f"{display}@{req.base_ref}")
            with cloner(req.repo_url, ref=req.head_ref) as head_path:
                candidate = run_scan(
                    head_path,
                    min_confidence=req.min_confidence,
                    display_target=f"{display}@{req.head_ref}",
                    ref=req.head_ref,
                )
                head_agents = _agent_report(head_path, candidate, f"{display}@{req.head_ref}")
        except CloneError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        payload = _to_drift_payload(baseline, candidate)
        payload["agent_privileges"] = _privilege_payload(
            payload, base_agents, head_agents, req
        )
        return payload

    @app.post("/api/diff/demo")
    def diff_demo(
        language: str = "python", scenario: str = "cross-file", revision: str = "candidate"
    ) -> dict[str, Any]:
        """Offline drift demo.

        ``scenario`` is ``cross-file`` (route, builder, agent and tool in four
        files) or ``same-file``.  ``revision=fixed`` compares the candidate with
        the fixed revision, the last step of the demo.
        """
        if language != "typescript":
            language = "python"  # unknown languages fall back, as before
        if scenario == "same-file":
            pair = ts_drift_demo_paths() if language == "typescript" else drift_demo_paths()
        elif scenario == "cross-file":
            pair = crossfile_drift_demo_paths(language)
        else:
            raise HTTPException(status_code=400, detail="scenario must be cross-file or same-file")
        if pair is None:
            raise HTTPException(
                status_code=503, detail=f"the built-in {language} drift demo is unavailable"
            )
        baseline_path, candidate_path = pair
        prefix = f"built-in://{scenario}/{language}"
        candidate = run_scan(candidate_path, display_target=f"{prefix}/candidate")
        if revision == "fixed":
            fixed = run_scan(baseline_path, display_target=f"{prefix}/fixed")
            return _to_drift_payload(candidate, fixed)
        baseline = run_scan(baseline_path, display_target=f"{prefix}/baseline")
        return _to_drift_payload(baseline, candidate)

    @app.post("/api/sarif")
    def sarif(
        req: ScanRequest, cloner: Annotated[Cloner, Depends(get_cloner)]
    ) -> dict[str, Any]:
        return to_sarif(_scan(req, cloner).findings)

    @app.post("/api/demo/sarif")
    def demo_sarif() -> dict[str, Any]:
        return to_sarif(_run_demo().findings)

    _mount_frontend(app)
    return app


def _validated_url(url: str) -> str:
    try:
        return normalize_repo_url(url)
    except CloneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _to_drift_payload(baseline: ScanResult, candidate: ScanResult) -> dict[str, Any]:
    """Drift plus the component counts that prove an inventory stayed identical."""
    report = compare_scan_results(baseline, candidate)
    return {
        "drift": report.model_dump(),
        "baseline": _revision_summary(baseline),
        "candidate": _revision_summary(candidate),
        # Kept for API compatibility; `drift.bom` states the compared scope.
        "components_identical": report.bom.identical if report.bom else False,
        "baseline_paths": _paths_payload(baseline),
        "candidate_paths": _paths_payload(candidate),
    }


def _agent_report(
    path: Path, result: ScanResult, label: str
) -> AgentSecurityReport | str:
    """The revision's agent analysis, or why it could not run."""
    try:
        return analyze_agents(path, result.inventory, display_target=label)
    except (InputError, FileNotFoundError) as exc:
        return str(exc)


def _privilege_payload(
    payload: dict[str, Any],
    before: AgentSecurityReport | str,
    after: AgentSecurityReport | str,
    req: DiffRequest,
) -> dict[str, Any]:
    """Agent privilege drift for a real repository, or the reason it was not evaluated.

    Needs ``aibom-identity.yaml`` (agent -> identity -> policy files) in the
    repository; without it nothing is guessed and the result says so.
    """
    if isinstance(before, str) or isinstance(after, str):
        return {"status": "failed",
                "reason": before if isinstance(before, str) else str(after)}
    if not (before.scope.manifest or after.scope.manifest):
        return {
            "status": "not_evaluated",
            "reason": "neither revision has an aibom-identity.yaml, so agents have no "
            "known identity or policy to compare",
        }
    bom = payload["drift"].get("bom") or {}
    report = compare_privileges(
        before,
        after,
        bom_identical=bom.get("identical"),
        bom_differences=[*bom.get("added", []), *bom.get("removed", []),
                         *bom.get("changed", [])],
        retest_command=f"aibom diff <baseline> <candidate> --agent-privileges "
        f"# {req.base_ref} vs {req.head_ref}",
    )
    return {"status": "evaluated", "report": report.model_dump(mode="json")}


def _paths_payload(result: ScanResult) -> dict[str, Any]:
    """Impact paths (proven and potential) plus unresolved candidates, for the graph."""
    return {
        "impact": [path.model_dump(mode="json") for path in build_impact_paths(result.inventory)],
        "unresolved": [
            path.model_dump(mode="json") for path in build_unresolved_impacts(result.inventory)
        ],
    }


def _revision_summary(result: ScanResult) -> dict[str, Any]:
    inv = result.inventory
    return {
        "target": inv.metadata.target,
        "counts": inv.counts(),
        "production_ai_components": production_ai_component_count(inv),
        "headline": headline(result.findings).model_dump(),
        "score": result.score.model_dump() | {"grade": result.score.grade},
        "findings": len(result.findings),
        # The revision's dependency map, so the drift and compare demos can show
        # what is connected to what, not only what changed.
        "graph": build_graph(inv, result.findings),
    }


async def _stream_scan(req: ScanRequest, cloner: Cloner) -> AsyncIterator[str]:
    cancel = threading.Event()
    lines: queue.Queue[dict[str, Any] | None] = queue.Queue()

    def report(stage: str) -> None:
        if cancel.is_set():
            raise ScanCancelled
        lines.put({"stage": stage})

    def work() -> None:
        try:
            result, agents = _scan_with_agents(req, cloner, progress=report)
            report("report")
            lines.put({"result": _to_payload(req.repo_url, result, agents)})
        except ScanCancelled:
            pass
        except HTTPException as exc:
            lines.put({"error": exc.detail, "status": exc.status_code})
        except Exception:
            log.exception("streamed scan failed")
            lines.put({"error": "internal error while scanning", "status": 500})
        finally:
            lines.put(None)

    threading.Thread(target=work, name="aibom-scan", daemon=True).start()
    try:
        while (item := await asyncio.to_thread(lines.get)) is not None:
            yield json.dumps(item) + "\n"
    finally:
        # Normal end, or the client disconnected: either way stop the worker.
        cancel.set()


def _scan(req: ScanRequest, cloner: Cloner) -> ScanResult:
    return _scan_with_agents(req, cloner, agents=False)[0]


def _agent_payload(path: Path, result: ScanResult, label: str) -> dict[str, Any]:
    """Agent -> MCP -> tool -> operation analysis, or the reason it could not run.

    Uses ``aibom-identity.yaml`` from the target when present (as the CLI does);
    without it every verdict is ``unknown``, never guessed.
    """
    try:
        report = analyze_agents(path, result.inventory, display_target=label)
    except (InputError, FileNotFoundError) as exc:
        return {"error": str(exc)}
    return report.model_dump(mode="json")


def _scan_with_agents(
    req: ScanRequest,
    cloner: Cloner,
    *,
    agents: bool = True,
    progress: Progress | None = None,
) -> tuple[ScanResult, dict[str, Any] | None]:
    report = progress or (lambda _stage: None)
    try:
        display = normalize_repo_url(req.repo_url)
    except CloneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        report("clone")
        clone_started = time.monotonic()
        ref = req.ref.strip() if req.ref and req.ref.strip() else None
        with (cloner(req.repo_url, ref=ref) if ref else cloner(req.repo_url)) as path:
            clone_ms = int((time.monotonic() - clone_started) * 1000)
            result = run_scan(
                path,
                resolve=req.resolve,
                vulns=req.vulns,
                min_confidence=req.min_confidence,
                display_target=display,
                ref=ref,
                progress=progress,
            )
            result.inventory.stats.clone_ms = clone_ms
            if agents:
                report("agents")
            agent_report = _agent_payload(path, result, display) if agents else None
            return result, agent_report
    except CloneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _run_demo() -> ScanResult:
    path = impact_demo_path()
    if path is None:
        raise HTTPException(status_code=503, detail="built-in impact demo is unavailable")
    return run_scan(
        path,
        resolve=False,
        vulns=False,
        display_target="built-in://impact-demo",
    )


def _to_payload(
    repo_url: str, result: ScanResult, agent_security: dict[str, Any] | None = None
) -> dict[str, Any]:
    inv = result.inventory
    policy_inventory = production_view(inv)
    bom = to_cyclonedx(inv)
    return {
        "repo_url": repo_url,
        "metadata": inv.metadata.model_dump(),
        "stats": inv.stats.model_dump(),
        "counts": inv.counts(),
        "analysis_scope": {
            "risk_context": "production",
            "production_counts": policy_inventory.counts(),
            "production_ai_components": production_ai_component_count(inv),
            "excluded_non_production_entities": (
                len(inv.entities) - len(policy_inventory.entities)
            ),
        },
        "headline": headline(result.findings).model_dump(),
        "coverage_notes": coverage_notes(inv),
        "score": result.score.model_dump() | {"grade": result.score.grade},
        "findings": [f.model_dump() for f in result.findings],
        "graph": build_graph(inv, result.findings),
        "dependencies": build_dependency_list(inv, result.findings),
        "vulnerable_packages": group_by_package(result.findings),
        "inventory": inv.model_dump(),
        "cyclonedx": bom,
        "minimum_elements": evaluate_cyclonedx(bom).to_dict(),
        "agent_security": agent_security,
    }


def _mount_frontend(app: FastAPI) -> None:
    """Serve the static UI at ``/`` when the bundled web dir is present."""
    web_dir = _find_web_dir()
    if web_dir is None:
        return
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(web_dir), html=True), name="web")


def _find_web_dir() -> Path | None:
    here = Path(__file__).resolve()
    env = os.environ.get("AIBOM_WEB_DIR")
    candidates = [
        # Explicit override (Docker image / any custom layout).
        *( [Path(env)] if env else [] ),
        # Installed wheel: web/ shipped inside the package as aibom/web.
        here.parents[1] / "web",
        # Source / editable layout: <root>/web next to <root>/src/aibom/…
        here.parents[3] / "web",
    ]
    for candidate in candidates:
        if (candidate / "index.html").exists():
            return candidate
    return None


# Convenience target for ``uvicorn aibom.server.app:app``.
app = create_app()
