"""The Docker image and the wheel agree, checked without Docker.

A Docker build is slow and not every machine has one, so what usually breaks
the image is pinned here as plain file checks: a path the wheel force-includes
that the Dockerfile never copies (the build fails, or a demo is missing), a
``.dockerignore`` rule that hides a file the Dockerfile needs, and a start
command that leaves ``sh`` as PID 1 (``docker stop`` and Cloud Run's SIGTERM
never reach uvicorn, so every stop waits out the kill timeout).
"""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")


def _copied_sources() -> set[str]:
    sources: set[str] = set()
    for line in DOCKERFILE.splitlines():
        match = re.match(r"^COPY\s+(?!--from)(.+)$", line.strip())
        if match:
            *srcs, _dest = match.group(1).split()
            sources.update(s.rstrip("/") for s in srcs)
    return sources


def _force_included() -> list[str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return list(data["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"])


def _dockerignore() -> list[str]:
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _ignored(path: str, patterns: list[str]) -> bool:
    """Docker's rule, simplified: a pattern matches the path or one of its parents."""
    parts = path.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for pattern in patterns:
        if pattern.startswith("!"):
            continue
        bare = pattern[3:] if pattern.startswith("**/") else pattern
        for prefix in prefixes:
            if fnmatch.fnmatch(prefix, pattern) or (
                pattern.startswith("**/") and fnmatch.fnmatch(prefix.split("/")[-1], bare)
            ):
                return True
    return False


def test_every_force_included_path_is_copied_into_the_build() -> None:
    copied = _copied_sources()
    missing = [p for p in _force_included() if p not in copied]
    assert not missing, f"Dockerfile does not COPY these wheel inputs: {missing}"


def test_the_build_copies_what_the_wheel_needs_to_build() -> None:
    copied = _copied_sources()
    assert {"pyproject.toml", "README.md", "LICENSE", "src"} <= copied


def test_dockerignore_hides_nothing_the_dockerfile_copies() -> None:
    patterns = _dockerignore()
    hidden = [src for src in _copied_sources() if _ignored(src, patterns)]
    assert not hidden, f".dockerignore excludes files the Dockerfile COPYs: {hidden}"
    # The demo's lockfile is what draws the bundled sample's dependency graph.
    assert not _ignored("tests/fixtures/impact-demo/uv.lock", patterns)


def test_dockerignore_keeps_the_heavy_local_directories_out() -> None:
    patterns = _dockerignore()
    for heavy in (".git", ".venv", "benchmark/checkouts", "verify-out", "aibom-out"):
        assert _ignored(heavy, patterns), heavy


def test_the_server_is_pid_1() -> None:
    cmd = [line for line in DOCKERFILE.splitlines() if line.startswith("CMD")]
    assert len(cmd) == 1
    assert "exec uvicorn" in cmd[0], "use `exec` so SIGTERM reaches uvicorn"
    assert "${PORT:-8000}" in cmd[0], "Cloud Run injects $PORT"


def test_deploy_smoke_posts_send_a_body() -> None:
    """Google Frontend answers a POST without Content-Length with 411.

    The deploy smoke test used ``curl -X POST`` with no body, which fails on
    Cloud Run however healthy the revision is (seen on aibom-inspector.com).
    """
    workflow = (ROOT / ".github" / "workflows" / "deploy-cloud-run.yml").read_text(
        encoding="utf-8"
    )
    curls = [line for line in workflow.splitlines() if line.strip().startswith("curl ")]
    posts = [c for c in curls if "-X POST" in c or "--data" in c or " -d " in c]
    assert posts, "the smoke test should exercise a POST endpoint"
    for line in posts:
        assert "--data" in line or " -d " in line, f"POST without a body: {line.strip()}"


def test_both_launchers_send_the_same_outputs_to_aibom_out() -> None:
    """/work is mounted read-only, so `./aibom scan . -c bom.json` failed with
    "Read-only file system" until the launchers mapped output paths to /out.
    """
    bash = (ROOT / "aibom").read_text(encoding="utf-8")
    ps1 = (ROOT / "aibom.ps1").read_text(encoding="utf-8")
    bash_match = re.search(r'^OUTPUT_FLAGS="([^"]+)"', bash, re.MULTILINE)
    ps1_match = re.search(r"\$outputFlags = @\(([^)]+)\)", ps1)
    assert bash_match and ps1_match
    bash_flags = set(bash_match.group(1).split())
    assert bash_flags == set(re.findall(r"'([^']+)'", ps1_match.group(1)))
    cli = (ROOT / "src" / "aibom" / "cli.py").read_text(encoding="utf-8")
    assert {"-o", "-c", "-r", "--sarif", "--agent-sarif", "--output-dir"} <= bash_flags
    unknown = [flag for flag in bash_flags if f'"{flag}"' not in cli]
    assert not unknown, f"launcher output flags the CLI does not define: {unknown}"


def test_cloud_run_serves_pages_while_one_scan_runs() -> None:
    """Concurrency 1 queued every page load behind a scan of up to 300 s.

    More than one request per instance is only safe in 1 GiB with clone-and-scan
    capped at one, so the two settings are checked together.
    """
    script = (ROOT / "scripts" / "deploy-cloud-run.sh").read_text(encoding="utf-8")
    concurrency = re.search(r"--concurrency (\d+)", script)
    assert concurrency
    if int(concurrency.group(1)) > 1:
        assert "AIBOM_MAX_CONCURRENT_SCANS=1" in script
    # The image itself opens no cross-origin access.
    assert "AIBOM_CORS_ORIGINS" not in re.sub(r"#.*", "", DOCKERFILE)


def test_the_launcher_runs_the_cli_as_the_host_user_on_posix() -> None:
    """The image's user (uid 10001) cannot write a host-owned ./aibom-out on
    Linux, so every `./aibom scan … -c bom.json` failed with Permission denied
    (caught by CI's docker job; Docker Desktop on Windows hides it).
    """
    bash = (ROOT / "aibom").read_text(encoding="utf-8")
    assert '--user "$(id -u):$(id -g)"' in bash
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "AIBOM_UID" in compose


def test_the_runtime_image_is_non_root() -> None:
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.MULTILINE)
    assert users and users[-1] not in {"root", "0"}
