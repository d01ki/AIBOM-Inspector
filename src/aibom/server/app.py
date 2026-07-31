"""FastAPI application: scan a public repo URL and return an AIBOM + risk report."""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractContextManager, asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from aibom import __version__
from aibom.demo import drift_demo_paths, impact_demo_path, ts_drift_demo_paths
from aibom.drift import compare_scan_results
from aibom.export.cyclonedx import to_cyclonedx
from aibom.export.sarif import to_sarif
from aibom.graph import build_graph
from aibom.policy import production_ai_component_count, production_view
from aibom.report.html import render_html
from aibom.server.clone import CloneError, clone_repo, normalize_repo_url
from aibom.service import ScanResult, run_scan

# A cloner takes a URL (and optional git ref) and returns a context manager
# yielding the checkout path.
Cloner = Callable[..., AbstractContextManager[Path]]


class ScanRequest(BaseModel):
    """Body for ``POST /api/scan`` and ``/api/report``.

    The backend has network by definition (it just cloned the repo), so
    enrichment — HF metadata resolution and OSV vulnerability mapping —
    defaults to on; pass ``resolve: false`` for a purely static scan.
    """

    repo_url: str = Field(description="Public repo URL, e.g. https://github.com/owner/repo")
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
        "  Quick demo: click \"Run built-in impact demo\" (no URL or network needed)\n"
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
        result = _scan(req, cloner)
        return _to_payload(req.repo_url, result)

    @app.post("/api/demo")
    def demo_scan() -> dict[str, Any]:
        result = _run_demo()
        return _to_payload("built-in://impact-demo", result)

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
                )
            with cloner(req.repo_url, ref=req.head_ref) as head_path:
                candidate = run_scan(
                    head_path,
                    min_confidence=req.min_confidence,
                    display_target=f"{display}@{req.head_ref}",
                )
        except CloneError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _to_drift_payload(baseline, candidate)

    @app.post("/api/diff/demo")
    def diff_demo(language: str = "python") -> dict[str, Any]:
        pair = ts_drift_demo_paths() if language == "typescript" else drift_demo_paths()
        if pair is None:
            raise HTTPException(
                status_code=503, detail=f"the built-in {language} drift demo is unavailable"
            )
        baseline_path, candidate_path = pair
        baseline = run_scan(
            baseline_path, display_target=f"built-in://drift/{language}/baseline"
        )
        candidate = run_scan(
            candidate_path, display_target=f"built-in://drift/{language}/candidate"
        )
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
        "components_identical": _component_signature(baseline)
        == _component_signature(candidate),
    }


def _revision_summary(result: ScanResult) -> dict[str, Any]:
    inv = result.inventory
    return {
        "target": inv.metadata.target,
        "counts": inv.counts(),
        "production_ai_components": production_ai_component_count(inv),
        "score": result.score.model_dump() | {"grade": result.score.grade},
        "findings": len(result.findings),
    }


def _component_signature(result: ScanResult) -> list[list[str]]:
    """Every non-prompt component, so 'same parts, new behavior' is checkable."""
    return sorted(
        [entity.type.value, entity.name, str(getattr(entity, "version", "") or "")]
        for entity in result.inventory.entities
        if entity.type.value != "prompt"
    )


def _scan(req: ScanRequest, cloner: Cloner) -> ScanResult:
    try:
        display = normalize_repo_url(req.repo_url)
    except CloneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        clone_started = time.monotonic()
        with cloner(req.repo_url) as path:
            clone_ms = int((time.monotonic() - clone_started) * 1000)
            result = run_scan(
                path,
                resolve=req.resolve,
                vulns=req.vulns,
                min_confidence=req.min_confidence,
                display_target=display,
            )
            result.inventory.stats.clone_ms = clone_ms
            return result
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


def _to_payload(repo_url: str, result: ScanResult) -> dict[str, Any]:
    inv = result.inventory
    policy_inventory = production_view(inv)
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
        "score": result.score.model_dump() | {"grade": result.score.grade},
        "findings": [f.model_dump() for f in result.findings],
        "graph": build_graph(inv, result.findings),
        "inventory": inv.model_dump(),
        "cyclonedx": to_cyclonedx(inv),
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
