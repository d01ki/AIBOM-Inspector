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
        "requests==2.31.0\n"  # not AI -> catalogued with ai=False
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
    assert pkgs["transformers"].usage.declared is True
    assert pkgs["transformers"].usage.imported is False
    assert pkgs["transformers"].detector_ids == ["manifest.dependencies"]


def test_pyproject_toml(tmp_path: Any) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'dependencies = ["anthropic>=0.25", "langchain-core==0.2.1", "flask>=3.0"]\n'
        "[project.optional-dependencies]\n"
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
        "{\n"
        '  "dependencies": {\n'
        '    "openai": "^4.0.0",\n'
        '    "@anthropic-ai/sdk": "0.20.0",\n'
        '    "express": "^4.18.0"\n'
        "  }\n"
        "}\n",
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
        "[tool.poetry.dependencies]\n"
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
        '[packages]\ntransformers = "==4.40.0"\nrequests = "*"\n[dev-packages]\nanthropic = "*"\n',
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
    assert len(pkgs) == 3  # complete BOM: everything catalogued
    assert all(p.ai is False for p in pkgs)  # type: ignore[attr-defined]
    assert inv.has_ai_components() is False  # ...but none of it counts as AI usage


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


# --- Phase 1: ecosystems beyond PyPI and npm --------------------------------


def test_go_mod_require_block_and_single_lines(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/agent\n\ngo 1.23\n\n"
        "require (\n"
        "\tgithub.com/sashabaranov/go-openai v1.32.0\n"
        "\tgithub.com/gin-gonic/gin v1.10.0 // indirect\n"
        ")\n\n"
        "require github.com/tmc/langchaingo v0.1.13\n",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["github.com/sashabaranov/go-openai"].ecosystem == "Go"
    assert pkgs["github.com/sashabaranov/go-openai"].version == "v1.32.0"
    assert pkgs["github.com/sashabaranov/go-openai"].ai is True
    assert pkgs["github.com/tmc/langchaingo"].ai is True
    assert pkgs["github.com/gin-gonic/gin"].ai is False
    assert pkgs["github.com/gin-gonic/gin"].purl == "pkg:golang/github.com/gin-gonic/gin@v1.10.0"


def test_go_module_major_version_suffix_still_matches_allowlist(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "require github.com/tmc/langchaingo/v2 v2.0.0\n", encoding="utf-8"
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["github.com/tmc/langchaingo/v2"].ai is True


def test_cargo_toml_table_and_string_specs(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nasync-openai = "0.24"\n'
        'tokio = { version = "1.38", features = ["full"] }\n'
        'serde = { version = "=1.0.203" }\n',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["async-openai"].ecosystem == "crates.io"
    assert pkgs["async-openai"].ai is True
    # A bare "0.24" means "^0.24" in Cargo, so it is not an exact pin.
    assert pkgs["async-openai"].version_pinned is False
    assert pkgs["tokio"].version == "1.38"
    assert pkgs["tokio"].ai is False
    assert pkgs["serde"].version_pinned is True


def test_pom_resolves_a_property_version(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><properties><openai.version>0.8.0</openai.version></properties>"
        "<dependencies>"
        "<dependency><groupId>com.openai</groupId><artifactId>openai-java</artifactId>"
        "<version>${openai.version}</version></dependency>"
        "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>"
        "<version>2.0.13</version></dependency>"
        "</dependencies></project>",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["com.openai:openai-java"].version == "0.8.0"
    assert pkgs["com.openai:openai-java"].ai is True
    assert pkgs["com.openai:openai-java"].purl == "pkg:maven/com.openai/openai-java@0.8.0"
    assert pkgs["org.slf4j:slf4j-api"].ai is False


def test_pom_with_a_namespace_is_parsed(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
        "<dependency><groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId>"
        "<version>0.34.0</version></dependency>"
        "</dependencies></project>",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["dev.langchain4j:langchain4j"].ai is True


def test_gradle_coordinates(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        'dependencies {\n'
        '    implementation("dev.langchain4j:langchain4j:0.34.0")\n'
        "    implementation 'org.slf4j:slf4j-api:2.0.13'\n"
        "}\n",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["dev.langchain4j:langchain4j"].version == "0.34.0"
    assert pkgs["dev.langchain4j:langchain4j"].ai is True
    assert pkgs["org.slf4j:slf4j-api"].ai is False


def test_gemfile(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(
        'source "https://rubygems.org"\n'
        'gem "ruby-openai", "7.3.1"\n'
        'gem "rails", "~> 7.1"\n'
        '# gem "commented-out", "1.0"\n',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["ruby-openai"].ecosystem == "RubyGems"
    assert pkgs["ruby-openai"].version_pinned is True
    assert pkgs["ruby-openai"].ai is True
    assert pkgs["rails"].version_pinned is False
    assert "commented-out" not in pkgs


def test_composer_skips_platform_requirements(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        '{"require": {"php": "^8.2", "ext-json": "*", '
        '"openai-php/client": "^0.10.3", "monolog/monolog": "^3.6"}}',
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert "php" not in pkgs and "ext-json" not in pkgs
    assert pkgs["openai-php/client"].ecosystem == "Packagist"
    assert pkgs["openai-php/client"].ai is True
    assert pkgs["monolog/monolog"].ai is False


def test_csproj_package_references(tmp_path: Path) -> None:
    (tmp_path / "Agent.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="Microsoft.SemanticKernel" Version="1.15.0" />'
        '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert pkgs["Microsoft.SemanticKernel"].ecosystem == "NuGet"
    assert pkgs["Microsoft.SemanticKernel"].ai is True
    assert pkgs["Newtonsoft.Json"].ai is False
    assert pkgs["Newtonsoft.Json"].purl == "pkg:nuget/Newtonsoft.Json@13.0.3"


def test_ordinary_dependencies_never_get_the_ai_flag(tmp_path: Path) -> None:
    """The AI flag drives the score, so a generic SBOM must not inherit it."""
    (tmp_path / "go.mod").write_text("require github.com/spf13/cobra v1.8.1\n", encoding="utf-8")
    (tmp_path / "Gemfile").write_text('gem "nokogiri", "1.16.5"\n', encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n', encoding="utf-8")
    inv = _scan(tmp_path)
    assert all(not p.ai for p in inv.by_type(EntityType.PACKAGE))
