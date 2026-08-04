"""Tests for the lockfile collector.

A lockfile is the only static source of the CISA 2026 *Component Hash*,
*Component Hash Algorithm* and transitive *Coverage* elements, so these tests
pin both the parsing and the resolved/declared merge behaviour.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.collectors.lockfiles import LockfileCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import DependencyScope, EntityType, Package

FIXTURE = Path(__file__).parent / "fixtures" / "locked-ai-app"


@pytest.fixture()
def locked() -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version="test", target=str(FIXTURE)))
    LockfileCollector(FIXTURE).collect(inv)
    return inv


def _pkg(inventory: Inventory, name: str) -> Package:
    matches = [
        e
        for e in inventory.by_type(EntityType.PACKAGE)
        if isinstance(e, Package) and e.name == name
    ]
    assert matches, f"{name} not collected"
    return matches[0]


def test_npm_integrity_becomes_a_hex_digest(locked: Inventory) -> None:
    openai = _pkg(locked, "openai")
    assert openai.version == "4.52.7"
    assert openai.hash_algorithm == "SHA-512"
    # sha512-<base64> is decoded to hex so CycloneDX can carry it.
    assert openai.content_hash is not None
    assert len(openai.content_hash) == 128
    assert set(openai.content_hash) <= set("0123456789abcdef")
    assert openai.producer == "registry.npmjs.org"
    assert openai.license == "Apache-2.0"


def test_transitive_dependencies_are_marked(locked: Inventory) -> None:
    assert _pkg(locked, "openai").dependency_scope is DependencyScope.DIRECT
    assert _pkg(locked, "form-data-encoder").dependency_scope is DependencyScope.TRANSITIVE


def test_poetry_prefers_the_sdist_digest(locked: Inventory) -> None:
    transformers = _pkg(locked, "transformers")
    assert transformers.version == "4.41.2"
    assert transformers.hash_algorithm == "SHA-256"
    assert transformers.content_hash == "0d0c" * 16
    assert transformers.hash_artifact == "transformers-4.41.2.tar.gz"


def test_uv_sdist_and_wheel_digests(locked: Inventory) -> None:
    assert _pkg(locked, "anthropic").content_hash == "7e" * 32
    # No sdist entry: the first wheel digest is used instead.
    assert _pkg(locked, "httpx").content_hash == "8f" * 32


def test_pipfile_lock_strips_the_version_pin(locked: Inventory) -> None:
    cohere = _pkg(locked, "cohere")
    assert cohere.version == "5.5.8"
    assert cohere.version_pinned is True
    assert cohere.ai is True


def test_hashed_requirements_are_collected(locked: Inventory) -> None:
    langchain = _pkg(locked, "langchain")
    assert langchain.version == "0.2.5"
    # Several --hash entries: one is chosen deterministically.
    assert langchain.content_hash == "3c" * 32
    assert langchain.hash_algorithm == "SHA-256"


def test_cargo_and_composer_and_gems(locked: Inventory) -> None:
    assert _pkg(locked, "candle-core").content_hash == "2b" * 32
    composer = _pkg(locked, "openai-php/client")
    assert composer.hash_algorithm == "SHA-1"
    assert composer.license == "MIT"
    # Gemfile.lock has no digests, but it does resolve the graph.
    gem = _pkg(locked, "faraday")
    assert gem.version == "2.9.0"
    assert gem.content_hash is None
    assert gem.producer == "rubygems.org"
    assert _pkg(locked, "ruby-openai").dependency_scope is DependencyScope.DIRECT


def test_evidence_points_at_the_lockfile(locked: Inventory) -> None:
    for name in ("openai", "transformers", "candle-core"):
        evidence = _pkg(locked, name).source_evidence[0]
        assert evidence.kind == "lockfile"
        assert evidence.line_start >= 1


def test_a_lockfile_pin_beats_a_manifest_range() -> None:
    """The manifest constrains, the lockfile resolves — the pin must win."""
    inv = Inventory(metadata=ScanMetadata(tool_version="test", target="t"))
    from aibom.collectors.dependencies import DependencyCollector

    DependencyCollector(FIXTURE).collect(inv)
    LockfileCollector(FIXTURE).collect(inv)
    openai = _pkg(inv, "openai")
    assert openai.version == "4.52.7"
    assert openai.version_pinned is True
    assert openai.content_hash is not None
    # One component, not two: the lockfile entry merged into the declared one.
    assert len([e for e in inv.by_type(EntityType.PACKAGE) if e.name == "openai"]) == 1


def test_a_malformed_lockfile_does_not_fail_the_scan(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{ this is not json", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("[[package]\nname = ", encoding="utf-8")
    inv = Inventory(metadata=ScanMetadata(tool_version="test", target=str(tmp_path)))
    LockfileCollector(tmp_path).collect(inv)
    assert inv.by_type(EntityType.PACKAGE) == []
