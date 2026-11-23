"""One repository walk for every collector: what is in the repository, and only that.

The code, manifest and lockfile collectors used to walk the tree separately,
with two different ignore lists, and only the code walk refused links out of
the scan root. A directory link (a POSIX symlink or a Windows junction) was
followed by all three, so a local scan of an untrusted checkout read and
reported files from outside it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aibom.service import run_scan


def _link_dir(link: Path, target: Path) -> None:
    """A directory link: a symlink where allowed, else a Windows junction."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    try:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    except (ImportError, AttributeError, OSError):
        pytest.skip("neither directory symlinks nor junctions are available")


def _repo_with_outside(tmp_path: Path) -> tuple[Path, Path]:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("fake-leak==1.0.0\n", encoding="utf-8")
    (outside / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/fake-lock-leak":'
        ' {"version": "1.0.0"}}}\n',
        encoding="utf-8",
    )
    (outside / "secret.py").write_text('import openai\nMODEL = "gpt-4.1"\n', encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    return root, outside


def test_a_directory_link_out_of_the_root_is_not_followed(tmp_path: Path) -> None:
    root, outside = _repo_with_outside(tmp_path)
    _link_dir(root / "linked", outside)
    inv = run_scan(root).inventory
    assert inv.stats.files_scanned == 1  # app.py only
    assert not any(m.startswith("linked/") for m in inv.stats.manifests_parsed)
    names = {e.name for e in inv.entities}
    assert "fake-leak" not in names
    assert "fake-lock-leak" not in names


def test_a_file_link_out_of_the_root_is_not_read_as_a_manifest(tmp_path: Path) -> None:
    root, outside = _repo_with_outside(tmp_path)
    try:
        (root / "requirements.txt").symlink_to(outside / "requirements.txt")
        (root / "package-lock.json").symlink_to(outside / "package-lock.json")
    except OSError:
        pytest.skip("symlinks are not available on this platform")
    inv = run_scan(root).inventory
    names = {e.name for e in inv.entities}
    assert "fake-leak" not in names
    assert "fake-lock-leak" not in names


def test_every_collector_ignores_the_same_directories(tmp_path: Path) -> None:
    """Build output and editor folders hold no first-party manifest."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"openai": "^4.0.0"}}\n', encoding="utf-8"
    )
    for ignored in (".next", ".cache", ".vscode", "node_modules/dep"):
        d = tmp_path / ignored
        d.mkdir(parents=True)
        (d / "package.json").write_text(
            '{"dependencies": {"ignored-dep": "1.0.0"}}\n', encoding="utf-8"
        )
        (d / "requirements.txt").write_text("ignored-req==1.0.0\n", encoding="utf-8")
    nested = tmp_path / "packages" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        '{"dependencies": {"nested-dep": "1.0.0"}}\n', encoding="utf-8"
    )
    inv = run_scan(tmp_path).inventory
    names = {e.name for e in inv.entities}
    assert {"openai", "nested-dep"} <= names
    assert "ignored-dep" not in names
    assert "ignored-req" not in names
    assert sorted(inv.stats.manifests_parsed) == ["package.json", "packages/web/package.json"]


def test_a_scan_root_inside_an_ignored_directory_still_scans(tmp_path: Path) -> None:
    """Ignore rules apply below the root, never to the root's own ancestors."""
    root = tmp_path / "venv" / "site-packages" / "app"
    root.mkdir(parents=True)
    (root / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    inv = run_scan(root).inventory
    assert "openai" in {e.name for e in inv.entities}
    assert inv.stats.manifests_parsed == ["requirements.txt"]
