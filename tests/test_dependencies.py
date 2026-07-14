"""Tests for the dependency-manifest collector."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom import __version__
from aibom.collectors.dependencies import DependencyCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import EntityType, Package


def _scan(tmp_path: Path) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    DependencyCollector(tmp_path).collect(inv)
    return inv


def _packages(inv: Inventory) -> dict[str, Package]:
    return {p.name: p for p in inv.by_type(EntityType.PACKAGE) if isinstance(p, Package)}


def test_requirements_txt(tmp_path: Any) -> None:
    (tmp_path / "requirements.txt").write_text(
        "transformers==4.40.0\n"
        "torch>=2.0\n"
        "requests==2.31.0\n"      # not AI -> catalogued with ai=False
        "openai\n"
        "# a comment\n"
        "-r other.txt\n",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert set(pkgs) == {"transformers", "torch", "openai", "requests"}
    assert pkgs["transformers"].ai is True
    assert pkgs["requests"].ai is False
    assert pkgs["transformers"].version == "4.40.0"
    assert pkgs["transformers"].version_pinned is True
    assert pkgs["transformers"].purl == "pkg:pypi/transformers@4.40.0"
    assert pkgs["torch"].version == "2.0"
    assert pkgs["torch"].version_pinned is False
    assert pkgs["openai"].version is None
    assert pkgs["requests"].version_pinned is True  # full BOM keeps exact pins too


def test_pyproject_toml(tmp_path: Any) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'dependencies = ["anthropic>=0.25", "langchain-core==0.2.1", "flask>=3.0"]\n'
        '[project.optional-dependencies]\n'
        'ml = ["sentence-transformers"]\n',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert set(pkgs) == {"anthropic", "langchain-core", "sentence-transformers", "flask"}
    assert pkgs["flask"].ai is False
    assert pkgs["langchain-core"].version == "0.2.1"
    assert pkgs["langchain-core"].version_pinned is True
    assert pkgs["anthropic"].version_pinned is False


def test_package_json(tmp_path: Any) -> None:
    (tmp_path / "package.json").write_text(
        '{\n'
        '  "dependencies": {\n'
        '    "openai": "^4.0.0",\n'
        '    "@anthropic-ai/sdk": "0.20.0",\n'
        '    "express": "^4.18.0"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert set(pkgs) == {"openai", "@anthropic-ai/sdk", "express"}
    assert pkgs["@anthropic-ai/sdk"].ai is True
    assert pkgs["express"].ai is False
    assert pkgs["openai"].ecosystem == "npm"
    assert pkgs["openai"].version == "4.0.0"
    assert pkgs["openai"].version_pinned is False
    assert pkgs["@anthropic-ai/sdk"].version_pinned is True
    assert pkgs["@anthropic-ai/sdk"].purl == "pkg:npm/@anthropic-ai/sdk@0.20.0"


def test_poetry_dependencies(tmp_path: Any) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\n'
        'python = "^3.10"\n'
        'torch = "^2.0.0"\n'
        'openai = "1.14.0"\n'
        'flask = "^3.0"\n',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert set(pkgs) == {"torch", "openai", "flask"}
    assert pkgs["openai"].version == "1.14.0"
    assert pkgs["openai"].version_pinned is True
    assert pkgs["torch"].version_pinned is False


def test_pipfile(tmp_path: Any) -> None:
    (tmp_path / "Pipfile").write_text(
        '[packages]\n'
        'transformers = "==4.40.0"\n'
        'requests = "*"\n'
        '[dev-packages]\n'
        'anthropic = "*"\n',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert set(pkgs) == {"transformers", "anthropic", "requests"}
    assert pkgs["transformers"].version == "4.40.0"
    assert pkgs["transformers"].version_pinned is True


def test_plain_deps_catalogued_but_not_ai(tmp_path: Any) -> None:
    (tmp_path / "requirements.txt").write_text("requests\nflask\nnumpy\n", encoding="utf-8")
    inv = _scan(tmp_path)
    pkgs = inv.by_type(EntityType.PACKAGE)
    assert len(pkgs) == 3                      # complete BOM: everything catalogued
    assert all(p.ai is False for p in pkgs)    # type: ignore[attr-defined]
    assert inv.has_ai_components() is False    # ...but none of it counts as AI usage


def test_same_name_across_ecosystems_stays_distinct(tmp_path: Any) -> None:
    (tmp_path / "requirements.txt").write_text("openai==1.14.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"openai": "4.0.0"}}\n', encoding="utf-8"
    )
    pkgs = _scan(tmp_path).by_type(EntityType.PACKAGE)
    ecosystems = {(p.name, p.ecosystem) for p in pkgs}  # type: ignore[attr-defined]
    assert ("openai", "PyPI") in ecosystems
    assert ("openai", "npm") in ecosystems


def test_every_package_has_evidence(tmp_path: Any) -> None:
    (tmp_path / "requirements.txt").write_text("transformers==4.40.0\n", encoding="utf-8")
    for p in _scan(tmp_path).by_type(EntityType.PACKAGE):
        assert p.source_evidence
        assert p.source_evidence[0].file == "requirements.txt"
        assert p.source_evidence[0].line_start == 1
