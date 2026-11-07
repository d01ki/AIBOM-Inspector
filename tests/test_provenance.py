"""Scan provenance: the analyzed commit is read from .git, never by running git."""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.provenance import read_commit, source_url_template
from aibom.service import run_scan

SHA = "0123456789abcdef0123456789abcdef01234567"


def _git(root: Path, head: str) -> Path:
    git = root / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(head + "\n", encoding="utf-8")
    return git


def test_detached_head_is_the_commit(tmp_path: Path) -> None:
    _git(tmp_path, SHA)
    assert read_commit(tmp_path) == SHA


def test_branch_head_reads_the_loose_ref(tmp_path: Path) -> None:
    git = _git(tmp_path, "ref: refs/heads/main")
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "refs" / "heads" / "main").write_text(SHA + "\n", encoding="utf-8")
    assert read_commit(tmp_path) == SHA


def test_branch_head_falls_back_to_packed_refs(tmp_path: Path) -> None:
    git = _git(tmp_path, "ref: refs/heads/main")
    (git / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n" f"{SHA} refs/heads/main\n",
        encoding="utf-8",
    )
    assert read_commit(tmp_path) == SHA


def test_no_git_or_a_hostile_ref_yields_none(tmp_path: Path) -> None:
    assert read_commit(tmp_path) is None
    _git(tmp_path, "ref: ../../etc/passwd")
    assert read_commit(tmp_path) is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/o/r", f"https://github.com/o/r/blob/{SHA}/{{path}}#L{{line}}"),
        ("https://github.com/o/r.git", f"https://github.com/o/r/blob/{SHA}/{{path}}#L{{line}}"),
        ("https://github.com/o/r@main", f"https://github.com/o/r/blob/{SHA}/{{path}}#L{{line}}"),
        ("https://gitlab.com/g/sub/r", f"https://gitlab.com/g/sub/r/-/blob/{SHA}/{{path}}#L{{line}}"),
        ("https://codeberg.org/o/r", f"https://codeberg.org/o/r/src/commit/{SHA}/{{path}}#L{{line}}"),
        ("https://bitbucket.org/o/r", f"https://bitbucket.org/o/r/src/{SHA}/{{path}}#lines-{{line}}"),
    ],
)
def test_source_links_are_pinned_to_the_commit(url: str, expected: str) -> None:
    assert source_url_template(url, SHA) == expected


def test_no_link_without_a_commit_or_for_an_unknown_host() -> None:
    assert source_url_template("https://github.com/o/r", None) is None
    assert source_url_template("https://github.com/o/r", "main") is None  # a branch moves
    assert source_url_template("https://example.com/o/r", SHA) is None
    assert source_url_template("/local/path", SHA) is None


def test_run_scan_records_ref_commit_and_link_template(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import openai\n", encoding="utf-8")
    _git(tmp_path, SHA)
    result = run_scan(tmp_path, display_target="https://github.com/o/r", ref="v1.2")
    meta = result.inventory.metadata
    assert meta.commit == SHA and meta.ref == "v1.2"
    assert meta.source_url_template is not None and SHA in meta.source_url_template
