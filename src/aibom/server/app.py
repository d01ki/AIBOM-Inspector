"""FastAPI application: scan a public repo URL and return an AIBOM + risk report."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from aibom import __version__
from aibom.export.cyclonedx import to_cyclonedx
from aibom.report.html import render_html
from aibom.server.clone import CloneError, clone_repo, normalize_repo_url
from aibom.service import ScanResult, run_scan

# A cloner takes a URL and returns a context manager yielding the checkout path.
Cloner = Callable[[str], AbstractContextManager[Path]]


class ScanRequest(BaseModel):
    """Body for ``POST /api/scan`` and ``/api/report``."""

    repo_url: str = Field(description="Public repo URL, e.g. https://github.com/owner/repo")
    resolve: bool = Field(default=False, description="Enrich HF models/datasets via the hub.")
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


def get_cloner() -> Cloner:
    """Dependency: the real clone implementation (overridden in tests)."""
    return clone_repo


def _cors_origins() -> list[str]:
    raw = os.environ.get("AIBOM_CORS_ORIGINS", "*").strip()
    return [o.strip() for o in raw.split(",") if o.strip()] or ["*"]


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIBOM Inspector API",
        version=__version__,
        summary="Discover, inventory, and risk-analyze AI supply chains from a repo URL.",
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

    @app.post("/api/report", response_class=HTMLResponse)
    def report(
        req: ScanRequest, cloner: Annotated[Cloner, Depends(get_cloner)]
    ) -> HTMLResponse:
        result = _scan(req, cloner)
        html = render_html(result.inventory, result.findings, result.score)
        return HTMLResponse(content=html)

    _mount_frontend(app)
    return app


def _scan(req: ScanRequest, cloner: Cloner) -> ScanResult:
    try:
        display = normalize_repo_url(req.repo_url)
    except CloneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        with cloner(req.repo_url) as path:
            return run_scan(
                path,
                resolve=req.resolve,
                min_confidence=req.min_confidence,
                display_target=display,
            )
    except CloneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _to_payload(repo_url: str, result: ScanResult) -> dict[str, Any]:
    inv = result.inventory
    return {
        "repo_url": repo_url,
        "metadata": inv.metadata.model_dump(),
        "counts": inv.counts(),
        "score": result.score.model_dump() | {"grade": result.score.grade},
        "findings": [f.model_dump() for f in result.findings],
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
    # repo layout: <root>/web and <root>/src/aibom/server/app.py
    candidate = Path(__file__).resolve().parents[3] / "web"
    return candidate if (candidate / "index.html").exists() else None


# Convenience target for ``uvicorn aibom.server.app:app``.
app = create_app()
