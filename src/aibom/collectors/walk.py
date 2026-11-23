"""The one walk of a repository that every collector shares.

What counts as "in the repository" is decided here, once:

* ignored directories (VCS metadata, virtualenvs, ``node_modules``, build
  output, editor folders) are pruned, so they are never descended into;
* a directory link (POSIX symlink or Windows junction) is never followed: its
  target is either outside the scan root or already walked directly;
* a file link is kept only when it resolves inside the scan root, so a link
  to a host file is never read.

Ignore rules apply to the path *below* the root only. The root's own
ancestors must not count, or a target that happens to live under, say,
``…/venv/site-packages/`` (the bundled demo app does) scans as empty.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

IGNORE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        "site-packages",
        ".idea",
        ".vscode",
        ".next",
        ".cache",
    }
)

_JUNCTION = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", None)


def repo_files(root: str | Path) -> list[Path]:
    """Every file in the repository at ``root``, sorted; a file root is itself."""
    base = Path(root).resolve()
    if base.is_file():
        return [base]
    real_base = os.path.realpath(base)
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in IGNORE_DIRS and not _is_dir_link(os.path.join(dirpath, d))
        ]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path) and not _inside(path, real_base):
                continue
            files.append(Path(path))
    return sorted(files)


def _is_dir_link(path: str) -> bool:
    try:
        if os.path.islink(path):
            return True
        tag = getattr(os.lstat(path), "st_reparse_tag", 0)
    except OSError:
        return True  # unreadable: do not descend
    return _JUNCTION is not None and tag == _JUNCTION


def _inside(path: str, real_base: str) -> bool:
    try:
        target = os.path.realpath(path)
        return os.path.commonpath([target, real_base]) == real_base
    except (OSError, ValueError):
        return False
