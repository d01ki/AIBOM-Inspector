"""Tests for the clone helper's subprocess handling.

``subprocess.run`` is faked so no real git or network is used; we verify the
error mapping, cleanup, and that a successful run yields (then removes) a dir.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from aibom.server import clone as clone_mod
from aibom.server.clone import CloneError, clone_repo

URL = "https://github.com/owner/repo"


def test_success_yields_then_cleans_up(monkeypatch: Any) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        # git would create the dest; emulate that so the scan target exists.
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)

    seen: Path | None = None
    with clone_repo(URL) as path:
        seen = path
        assert path.exists()
    assert seen is not None
    assert not seen.exists()  # cleaned up on exit


def test_clone_failure_maps_to_cloneerror(monkeypatch: Any) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> None:
        raise subprocess.CalledProcessError(128, cmd, "", "fatal: repository not found")

    monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
    with pytest.raises(CloneError, match="repository not found"), clone_repo(URL):
        pass


def test_timeout_maps_to_cloneerror(monkeypatch: Any) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd, 5)

    monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
    with pytest.raises(CloneError, match="timed out"), clone_repo(URL, timeout=5):
        pass


def test_missing_git_maps_to_cloneerror(monkeypatch: Any) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> None:
        raise FileNotFoundError("git")

    monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
    with pytest.raises(CloneError, match="git is not available"), clone_repo(URL):
        pass


def test_invalid_url_rejected_before_subprocess(monkeypatch: Any) -> None:
    called = False

    def fake_run(cmd: list[str], **kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
    with pytest.raises(CloneError), clone_repo("ftp://evil/owner/repo"):
        pass
    assert called is False  # validation happens before git runs
