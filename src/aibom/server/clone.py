"""Safe, shallow clone of a public git repository into a throwaway directory.

Hardening:

* **Host allowlist.** Only well-known public forges are accepted, blocking SSRF
  to internal hosts and non-http schemes.
* **Strict URL validation.** The URL must match an ``owner/repo`` shape before it
  is ever passed to git, and it is passed as an argv element (never a shell
  string), so it cannot inject flags or commands.
* **Shallow + capped.** ``--depth 1`` with a wall-clock timeout keeps a hostile
  or huge repository from exhausting the box.
* **Isolated & cleaned.** Each clone lives in its own temp dir, removed on exit.
* **Bounded checkout.** Symlinks are checked out as plain files (they can
  never point the scanner outside the checkout), and a checkout larger than
  ``AIBOM_MAX_CLONE_MB`` (default 300) or ``AIBOM_MAX_CLONE_FILES`` (default
  60000) is rejected before any scanning.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Public forges we accept. Add more here deliberately, not from user input.
_ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}

_URL_RE = re.compile(
    r"^https://(?P<host>[a-z0-9.\-]+)/(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)

_DEFAULT_TIMEOUT = 120  # seconds

# A branch, tag, or commit SHA. Deliberately strict: the value reaches git as an
# argv element, and a leading '-' or '..' must never be mistaken for a flag or a
# revision range.
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,199}$")


def normalize_ref(ref: str) -> str:
    """Validate a git ref, raising :class:`CloneError` when it is unusable."""
    candidate = (ref or "").strip()
    if not _REF_RE.match(candidate) or ".." in candidate or candidate.endswith("/"):
        raise CloneError(
            f"invalid git ref '{ref}' — use a branch, tag, or commit SHA"
        )
    return candidate


class CloneError(RuntimeError):
    """Raised when a repository URL is rejected or the clone fails."""


def normalize_repo_url(url: str) -> str:
    """Validate ``url`` and return a canonical ``https://host/owner/repo.git``.

    Raises :class:`CloneError` for anything not on the host allowlist or not
    shaped like a repository URL.
    """
    candidate = (url or "").strip()
    m = _URL_RE.match(candidate)
    if not m:
        raise CloneError(
            "invalid repository URL — expected https://<forge>/<owner>/<repo>"
        )
    host = m.group("host").lower()
    if host not in _ALLOWED_HOSTS:
        allowed = ", ".join(sorted(_ALLOWED_HOSTS))
        raise CloneError(f"host '{host}' is not allowed (allowed: {allowed})")
    owner, repo = m.group("owner"), m.group("repo")
    if owner in {".", ".."} or repo in {".", ".."}:
        raise CloneError("invalid owner/repo in URL")
    return f"https://{host}/{owner}/{repo}.git"


@contextmanager
def clone_repo(
    url: str, *, ref: str | None = None, timeout: int = _DEFAULT_TIMEOUT
) -> Iterator[Path]:
    """Shallow-clone ``url`` into a temp dir, yielding its path; clean up after.

    With ``ref`` the checkout is pinned to that branch, tag, or commit — the
    revision pair a behavioral drift comparison needs.
    """
    normalized = normalize_repo_url(url)
    pinned = normalize_ref(ref) if ref else None
    workdir = Path(tempfile.mkdtemp(prefix="aibom-clone-"))
    dest = workdir / "repo"
    try:
        commands = (
            _pinned_commands(normalized, dest, pinned)
            if pinned
            else [("clone", _clone_command(normalized, dest))]
        )
        for label, command in commands:
            _run_git(label, command, timeout=timeout)
        enforce_checkout_limits(dest)
        yield dest
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


_SAFE_CONFIG = (
    "-c", "credential.helper=",
    "-c", "core.askPass=",
    "-c", "core.symlinks=false",
    "-c", "protocol.file.allow=never",
)


def _limit(name: str, default: int) -> int:
    import os

    try:
        return max(1, int(os.environ.get(name, default)))
    except ValueError:
        return default


def enforce_checkout_limits(root: Path) -> None:
    """Reject a checkout too large to scan safely (resource exhaustion)."""
    import os

    max_bytes = _limit("AIBOM_MAX_CLONE_MB", 300) * 1024 * 1024
    max_files = _limit("AIBOM_MAX_CLONE_FILES", 60_000)
    total = files = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            if entry.name == ".git":
                continue
            if entry.is_dir(follow_symlinks=False):
                stack.append(Path(entry.path))
                continue
            files += 1
            try:
                total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if files > max_files or total > max_bytes:
                raise CloneError(
                    "repository is too large to scan here "
                    f"(limits: {max_files} files, {max_bytes // (1024 * 1024)} MB)"
                )


def _clone_command(url: str, dest: Path) -> list[str]:
    return [
        "git", *_SAFE_CONFIG,
        "clone", "--depth", "1", "--single-branch",
        "--no-tags", "--config", "protocol.version=2",
        url, str(dest),
    ]


def _pinned_commands(url: str, dest: Path, ref: str) -> list[tuple[str, list[str]]]:
    """Fetch exactly one revision — works for branches, tags, and commit SHAs."""
    dest.mkdir(parents=True, exist_ok=True)
    base = ["git", *_SAFE_CONFIG, "-C", str(dest)]
    return [
        ("init", ["git", "init", "--quiet", str(dest)]),
        ("remote add", [*base, "remote", "add", "origin", url]),
        ("fetch", [*base, "fetch", "--depth", "1", "--no-tags", "origin", ref]),
        ("checkout", [*base, "checkout", "--quiet", "FETCH_HEAD"]),
    ]


def _run_git(label: str, command: list[str], *, timeout: int) -> None:
    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_git_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise CloneError(f"git {label} timed out after {timeout}s") from exc
    except subprocess.CalledProcessError as exc:
        raise CloneError(f"git {label} failed: {_last_line(exc.stderr)}") from exc
    except FileNotFoundError as exc:  # git not installed
        raise CloneError("git is not available on the server") from exc


def _path() -> str:
    import os

    return os.environ.get("PATH", "/usr/bin:/bin")


# Host variables the OS itself needs for git to run at all. On Windows, Winsock
# cannot initialise without SYSTEMROOT and every clone fails with
# "getaddrinfo() thread failed to start". Nothing git-specific (GIT_*, config,
# credentials) is passed through.
_OS_ENV = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")


def _git_env() -> dict[str, str]:
    import os

    env = {k: os.environ[k] for k in _OS_ENV if k in os.environ}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true", "PATH": _path()})
    return env


def _last_line(text: str | None) -> str:
    if not text:
        return "unknown error"
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    return lines[-1] if lines else "unknown error"
