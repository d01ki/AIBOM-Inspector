"""Scan provenance: which commit was analyzed, and links to its source lines.

A result is only reproducible if it names the exact revision it describes. The
commit is read from the checkout's ``.git`` directory as plain files (no git
process, nothing from the repository is executed), and evidence locations can
then link to that commit — never to a moving branch.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

_SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_MAX_BYTES = 1 << 20  # packed-refs of a shallow clone is tiny; refuse anything odd


def read_commit(root: str | Path) -> str | None:
    """The commit ``HEAD`` points at in ``root``, or None if it cannot be read."""
    git = Path(root) / ".git"
    try:
        if git.is_file():  # worktree / submodule: "gitdir: <path>"
            text = _read(git)
            if not text or not text.startswith("gitdir:"):
                return None
            git = (Path(root) / text.split(":", 1)[1].strip()).resolve()
        head = _read(git / "HEAD")
        if head is None:
            return None
        if _SHA.match(head):
            return head
        if not head.startswith("ref:"):
            return None
        ref = head.split(":", 1)[1].strip()
        if ".." in ref or not ref.startswith("refs/"):
            return None
        loose = _read(git / ref)
        if loose and _SHA.match(loose):
            return loose
        packed = _read(git / "packed-refs") or ""
        for line in packed.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref and _SHA.match(parts[0]):
                return parts[0]
    except OSError:
        return None
    return None


def _read(path: Path) -> str | None:
    if not path.is_file() or path.stat().st_size > _MAX_BYTES:
        return None
    return path.read_text(encoding="utf-8", errors="replace").strip()


def source_url_template(repo_url: str, commit: str | None) -> str | None:
    """A ``{path}`` / ``{line}`` URL template pinned to ``commit`` on a known host."""
    if not commit or not _SHA.match(commit):
        return None
    parsed = urlparse(repo_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return None
    path = parsed.path.split("@", 1)[0].rstrip("/")  # drop a drift "@ref" suffix
    if path.endswith(".git"):
        path = path[:-4]
    if path.count("/") < 2:
        return None
    base = f"https://{parsed.hostname}{path}"
    host = parsed.hostname.lower()
    if host in {"github.com", "www.github.com"}:
        return f"{base}/blob/{commit}/{{path}}#L{{line}}"
    if host == "gitlab.com":
        return f"{base}/-/blob/{commit}/{{path}}#L{{line}}"
    if host == "codeberg.org":
        return f"{base}/src/commit/{commit}/{{path}}#L{{line}}"
    if host == "bitbucket.org":
        return f"{base}/src/{commit}/{{path}}#lines-{{line}}"
    return None
