"""DependencyCollector — inventory every dependency declared in manifests.

Reads ``requirements*.txt``, ``pyproject.toml``, ``Pipfile`` (PyPI) and
``package.json`` (npm), and emits a :class:`~aibom.models.entities.Package` for
**every** dependency — a complete BOM — flagging the ones that belong to the
AI/ML ecosystem (``Package.ai``). The AI layer (models, prompts, agents,
services + AI-aware risk rules) is what this tool adds on top of a conventional
SBOM. It parses text only — it never installs or runs anything.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from aibom.collectors.base import Collector
from aibom.detectors.python.parser import classify_source_context
from aibom.inventory import Inventory
from aibom.models.analysis import ConfidenceFactors, UsageState
from aibom.models.entities import Package
from aibom.models.evidence import Evidence

_IGNORE_DIRS = {
    ".git",
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
}

# AI/ML ecosystem allowlist (normalized: lowercase, '_' -> '-'). Kept curated so
# the AIBOM stays AI-focused rather than becoming a general SBOM.
_AI_PYPI = {
    "transformers",
    "torch",
    "torchvision",
    "torchaudio",
    "tensorflow",
    "keras",
    "jax",
    "jaxlib",
    "flax",
    "openai",
    "openai-agents",
    "anthropic",
    "cohere",
    "mistralai",
    "google-generativeai",
    "google-genai",
    "litellm",
    "langgraph",
    "llama-index",
    "llama-cpp-python",
    "ctransformers",
    "vllm",
    "sglang",
    "text-generation",
    "sentence-transformers",
    "diffusers",
    "accelerate",
    "datasets",
    "huggingface-hub",
    "tokenizers",
    "safetensors",
    "ollama",
    "guidance",
    "instructor",
    "autogen",
    "autogenstudio",
    "pyautogen",
    "crewai",
    "haystack-ai",
    "onnxruntime",
    "onnx",
    "optimum",
    "timm",
    "peft",
    "trl",
    "bitsandbytes",
    "sentencepiece",
    "gpt4all",
    "openai-whisper",
    "spacy",
    "scikit-learn",
    "xgboost",
    "lightgbm",
    "catboost",
    "replicate",
    "groq",
    "instructorai",
    "mcp",
    "fastmcp",
    "modelcontextprotocol",
}
_AI_PYPI_PREFIXES = ("langchain", "llama-index", "llamaindex", "llama-cpp")

_AI_NPM = {
    "openai",
    "@anthropic-ai/sdk",
    "@google/generative-ai",
    "@google/genai",
    "cohere-ai",
    "@mistralai/mistralai",
    "ai",
    "langchain",
    "llamaindex",
    "ollama",
    "replicate",
    "groq-sdk",
    "openai-edge",
    "fastmcp",
}
_AI_NPM_PREFIXES = (
    "@langchain/",
    "@llamaindex/",
    "@huggingface/",
    "@ai-sdk/",
    "@anthropic-ai/",
    "@modelcontextprotocol/",
)

# Curated per-ecosystem AI allowlists. Exact names plus prefixes - the same
# precision-first shape as PyPI/npm. A substring match would flag things like
# "openapi-generator", and the ai flag drives the risk score.
_AI_GO = {
    "github.com/openai/openai-go",
    "github.com/sashabaranov/go-openai",
    "github.com/anthropics/anthropic-sdk-go",
    "github.com/tmc/langchaingo",
    "github.com/google/generative-ai-go",
    "github.com/ollama/ollama",
    "github.com/mark3labs/mcp-go",
    "github.com/cohere-ai/cohere-go",
}
_AI_GO_PREFIXES = ("github.com/tmc/langchaingo/", "github.com/modelcontextprotocol/")

_AI_CARGO = {
    "async-openai",
    "openai-api-rs",
    "anthropic-sdk",
    "langchain-rust",
    "tch",
    "ort",
    "tokenizers",
    "hf-hub",
    "llama-cpp-2",
    "rmcp",
}
_AI_CARGO_PREFIXES = ("candle-", "llm-chain", "rig-")

_AI_MAVEN = {
    "com.theokanning.openai-gpt3-java:service",
}
_AI_MAVEN_PREFIXES = (
    "dev.langchain4j:",
    "ai.djl:",
    "org.deeplearning4j:",
    "io.modelcontextprotocol:",
    "org.springframework.ai:",
    "com.openai:",
    "com.anthropic:",
)

_AI_RUBYGEMS = {
    "ruby-openai",
    "anthropic",
    "ruby-anthropic",
    "informers",
    "transformers-rb",
    "mcp",
}
_AI_RUBYGEMS_PREFIXES = ("langchainrb",)

_AI_PACKAGIST = {
    "theodo-group/llphant",
    "anthropic-php/anthropic-sdk-php",
    "logiscape/mcp-sdk-php",
}
_AI_PACKAGIST_PREFIXES = ("openai-php/", "llm-agents/")

_AI_NUGET = {
    "openai",
    "anthropic.sdk",
    "langchain",
    "modelcontextprotocol",
    "ollamasharp",
}
_AI_NUGET_PREFIXES = ("microsoft.semantickernel", "microsoft.ml", "langchain.", "azure.ai.")

_MANIFEST_NAMES = {
    "pyproject.toml",
    "pipfile",
    "package.json",
    "go.mod",
    "cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "composer.json",
}

_RE_REQ = re.compile(
    r"""^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"""
    r"""(?:(===|==|~=|>=|<=|!=|>|<)\s*([A-Za-z0-9][A-Za-z0-9._*+!-]*))?"""
)

# go.mod: "require github.com/x/y v1.2.3" and entries inside a require block.
_RE_GO_REQUIRE = re.compile(
    r"""^\s*(?:require\s+)?([A-Za-z0-9][\w.\-]*(?:\.[A-Za-z]{2,})?/[\w.\-/~]+)\s+(v[\w.\-+]+)"""
)
# Gemfile: gem "name", "~> 1.2"
_RE_GEMFILE = re.compile(
    r"""^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?"""
)
# Gradle: implementation("group:artifact:version") or 'group:artifact:version'
_RE_GRADLE = re.compile(
    r"""["']([A-Za-z0-9][\w.\-]*:[\w.\-]+)(?::([\w.\-+]+))?["']"""
)
# csproj: <PackageReference Include="Name" Version="1.2.3" />
_RE_CSPROJ = re.compile(
    r"""<PackageReference\s+[^>]*Include\s*=\s*["']([^"']+)["']"""
    r"""(?:[^>]*Version\s*=\s*["']([^"']+)["'])?""",
    re.IGNORECASE,
)
_RE_PEP508_NAME = re.compile(r"""^\s*([A-Za-z0-9][A-Za-z0-9._-]*)""")
_RE_PIN = re.compile(r"""===?\s*([^,;\s]+)""")
_RE_RANGE = re.compile(r"""(?:~=|>=|<=|!=|>|<|\^|~)\s*([0-9][^,;\s]*)""")


def _load_toml(raw: str) -> dict[str, Any] | None:
    """Parse TOML using the stdlib ``tomllib`` (3.11+) or the ``tomli`` backport."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return None
    try:
        result = tomllib.loads(raw)
    except (ValueError, TypeError):
        return None
    return result if isinstance(result, dict) else None


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", ".").replace(".", "-").strip("-")


def _is_ai_pypi(name: str) -> bool:
    n = _norm(name)
    return n in _AI_PYPI or n.startswith(_AI_PYPI_PREFIXES)


def _is_ai_npm(name: str) -> bool:
    n = name.strip().lower()
    return n in _AI_NPM or n.startswith(_AI_NPM_PREFIXES)


# ecosystem -> (exact names, name prefixes), all compared lowercase.
_AI_BY_ECOSYSTEM: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {
    "go": (frozenset(_AI_GO), _AI_GO_PREFIXES),
    "crates.io": (frozenset(_AI_CARGO), _AI_CARGO_PREFIXES),
    "maven": (frozenset(_AI_MAVEN), _AI_MAVEN_PREFIXES),
    "rubygems": (frozenset(_AI_RUBYGEMS), _AI_RUBYGEMS_PREFIXES),
    "packagist": (frozenset(_AI_PACKAGIST), _AI_PACKAGIST_PREFIXES),
    "nuget": (frozenset(_AI_NUGET), _AI_NUGET_PREFIXES),
}


def _is_ai_package(name: str, ecosystem: str) -> bool:
    """Decide the AI flag for any supported ecosystem."""
    eco = ecosystem.strip().lower()
    if eco == "pypi":
        return _is_ai_pypi(name)
    if eco == "npm":
        return _is_ai_npm(name)
    table = _AI_BY_ECOSYSTEM.get(eco)
    if table is None:
        return False
    exact, prefixes = table
    normalized = name.strip().lower()
    # Go modules are often versioned (".../v2"); the suffix is not part of the
    # identity for allowlist purposes.
    if eco == "go":
        normalized = re.sub(r"/v[0-9]+$", "", normalized)
    return normalized in exact or normalized.startswith(prefixes)


class DependencyCollector(Collector):
    """Scan dependency manifests for AI/ML packages."""

    name = "dependencies"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def collect(self, inventory: Inventory) -> None:
        if "manifest.dependencies" not in inventory.stats.detectors_run:
            inventory.stats.detectors_run.append("manifest.dependencies")
        for path in self._iter_manifests():
            rel = self._rel(path)
            name = path.name.lower()
            try:
                if name.startswith("requirements") and name.endswith(".txt"):
                    self._parse_requirements(inventory, path, rel)
                elif name == "pyproject.toml":
                    self._parse_pyproject(inventory, path, rel)
                elif name == "pipfile":
                    self._parse_pipfile(inventory, path, rel)
                elif name == "package.json":
                    self._parse_package_json(inventory, path, rel)
                elif name == "go.mod":
                    self._parse_go_mod(inventory, path, rel)
                elif name == "cargo.toml":
                    self._parse_cargo_toml(inventory, path, rel)
                elif name == "pom.xml":
                    self._parse_pom(inventory, path, rel)
                elif name in {"build.gradle", "build.gradle.kts"}:
                    self._parse_gradle(inventory, path, rel)
                elif name == "gemfile":
                    self._parse_gemfile(inventory, path, rel)
                elif name == "composer.json":
                    self._parse_composer(inventory, path, rel)
                elif name.endswith(".csproj"):
                    self._parse_csproj(inventory, path, rel)
                else:
                    continue
            except (OSError, ValueError):
                continue
            if rel not in inventory.stats.manifests_parsed:
                inventory.stats.manifests_parsed.append(rel)

    # -- iteration -------------------------------------------------------------

    def _iter_manifests(self) -> list[Path]:
        if self.root.is_file():
            return [self.root]
        out: list[Path] = []
        for path in self.root.rglob("*"):
            # Relative parts only: the scan root's own ancestors (e.g. a venv's
            # site-packages holding the bundled demo app) must not exclude it.
            if path.is_dir() or any(p in _IGNORE_DIRS for p in path.relative_to(self.root).parts):
                continue
            n = path.name.lower()
            if (
                (n.startswith("requirements") and n.endswith(".txt"))
                or n.endswith(".csproj")
                or n in _MANIFEST_NAMES
            ):
                out.append(path)
        return sorted(out)

    def _rel(self, path: Path) -> str:
        base = self.root if self.root.is_dir() else self.root.parent
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            return path.as_posix()

    # -- emit ------------------------------------------------------------------

    def _emit(
        self,
        inventory: Inventory,
        rel: str,
        lineno: int,
        snippet: str,
        name: str,
        ecosystem: str,
        version: str | None,
        pinned: bool,
    ) -> None:
        ai = _is_ai_package(name, ecosystem)
        ev = Evidence(
            file=rel,
            line_start=lineno,
            line_end=lineno,
            snippet=snippet.strip()[:200],
            matched_pattern=f"{ecosystem.lower()}-dependency",
            confidence=0.9,
            detector_id="manifest.dependencies",
            kind="manifest",
        )
        inventory.add_entity(
            Package(
                name=name,
                ecosystem=ecosystem,
                version=version,
                version_pinned=pinned,
                ai=ai,
                source_evidence=[ev],
                detector_ids=["manifest.dependencies"],
                usage=UsageState(declared=True),
                confidence_factors=ConfidenceFactors(
                    syntax_confidence=0.95,
                    value_resolution_confidence=0.9,
                    framework_identification_confidence=1.0 if ai else 0.9,
                ),
                source_contexts=[classify_source_context(rel)],
            )
        )

    # -- parsers ---------------------------------------------------------------

    def _parse_requirements(self, inventory: Inventory, path: Path, rel: str) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            m = _RE_REQ.match(stripped)
            if not m:
                continue
            op, ver = m.group(2), m.group(3)
            pinned = op in {"==", "==="}
            self._emit(
                inventory, rel, lineno, line, m.group(1), "PyPI", ver if op else None, pinned
            )

    def _parse_pyproject(self, inventory: Inventory, path: Path, rel: str) -> None:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = _load_toml(raw)
        if data is None:
            return
        lines = raw.splitlines()
        project = data.get("project", {})
        specs: list[str] = list(project.get("dependencies", []) or [])
        for group in (project.get("optional-dependencies", {}) or {}).values():
            specs.extend(group or [])
        for spec in specs:
            self._emit_pep508(inventory, rel, lines, spec)
        # Poetry-style table
        poetry = data.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies"):
            for name, ver in (poetry.get(section, {}) or {}).items():
                if name.lower() == "python":
                    continue
                self._emit_named(inventory, rel, lines, name, _spec_version(ver))

    def _parse_pipfile(self, inventory: Inventory, path: Path, rel: str) -> None:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = _load_toml(raw)
        if data is None:
            return
        lines = raw.splitlines()
        for section in ("packages", "dev-packages"):
            for name, ver in (data.get(section, {}) or {}).items():
                self._emit_named(inventory, rel, lines, name, _spec_version(ver))

    def _parse_package_json(self, inventory: Inventory, path: Path, rel: str) -> None:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        lines = raw.splitlines()
        sections = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
        for section in sections:
            for name, spec in (data.get(section, {}) or {}).items():
                version, pinned = _npm_version(str(spec))
                self._emit(
                    inventory,
                    rel,
                    _find_line(lines, f'"{name}"'),
                    f'"{name}": "{spec}"',
                    name,
                    "npm",
                    version,
                    pinned,
                )

    # -- other ecosystems ------------------------------------------------------

    def _parse_go_mod(self, inventory: Inventory, path: Path, rel: str) -> None:
        """go.mod: single `require` lines and `require ( ... )` blocks."""
        text = path.read_text(encoding="utf-8", errors="replace")
        in_block = False
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.split("//", 1)[0].strip()
            if not stripped:
                continue
            if stripped.startswith("require") and stripped.endswith("("):
                in_block = True
                continue
            if in_block and stripped == ")":
                in_block = False
                continue
            if not in_block and not stripped.startswith("require "):
                continue
            match = _RE_GO_REQUIRE.match(stripped)
            if match:
                # Go versions in go.mod are exact resolved versions.
                self._emit(
                    inventory, rel, lineno, line, match.group(1), "Go", match.group(2), True
                )

    def _parse_cargo_toml(self, inventory: Inventory, path: Path, rel: str) -> None:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = _load_toml(raw)
        if data is None:
            return
        lines = raw.splitlines()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in (data.get(section, {}) or {}).items():
                version, pinned = _cargo_version(spec)
                self._emit(
                    inventory,
                    rel,
                    _find_line(lines, name),
                    f"{name} = {spec}",
                    str(name),
                    "crates.io",
                    version,
                    pinned,
                )

    def _parse_pom(self, inventory: Inventory, path: Path, rel: str) -> None:
        """Maven POM. Parsed with the stdlib XML reader, entities disabled."""
        from xml.etree import ElementTree  # noqa: S405 - defused below

        raw = path.read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()
        try:
            # No custom parser: ElementTree ignores DTDs and does not expand
            # external entities, so a hostile pom cannot reach the filesystem.
            root = ElementTree.fromstring(raw)  # noqa: S314
        except ElementTree.ParseError:
            return
        namespace = root.tag.partition("}")[0].lstrip("{") if root.tag.startswith("{") else ""
        prefix = f"{{{namespace}}}" if namespace else ""
        properties = {
            child.tag[len(prefix):]: (child.text or "").strip()
            for child in root.findall(f"{prefix}properties/*")
        }
        for dependency in root.iter(f"{prefix}dependency"):
            group = dependency.findtext(f"{prefix}groupId", default="").strip()
            artifact = dependency.findtext(f"{prefix}artifactId", default="").strip()
            if not group or not artifact:
                continue
            version = _resolve_maven_version(
                dependency.findtext(f"{prefix}version", default="").strip(), properties
            )
            self._emit(
                inventory,
                rel,
                _find_line(lines, artifact),
                f"{group}:{artifact}",
                f"{group}:{artifact}",
                "Maven",
                version or None,
                bool(version),
            )

    def _parse_gradle(self, inventory: Inventory, path: Path, rel: str) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.split("//", 1)[0]
            for match in _RE_GRADLE.finditer(stripped):
                coordinate, version = match.group(1), match.group(2)
                if coordinate.count(":") != 1:
                    continue
                self._emit(
                    inventory, rel, lineno, line, coordinate, "Maven", version, bool(version)
                )

    def _parse_gemfile(self, inventory: Inventory, path: Path, rel: str) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.split("#", 1)[0]
            match = _RE_GEMFILE.match(stripped)
            if not match:
                continue
            constraint = match.group(2)
            version, pinned = _gem_version(constraint)
            self._emit(
                inventory, rel, lineno, line, match.group(1), "RubyGems", version, pinned
            )

    def _parse_composer(self, inventory: Inventory, path: Path, rel: str) -> None:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        lines = raw.splitlines()
        for section in ("require", "require-dev"):
            for name, spec in (data.get(section, {}) or {}).items():
                if "/" not in str(name):  # php, ext-*, composer-plugin-api
                    continue
                version, pinned = _npm_version(str(spec))
                self._emit(
                    inventory,
                    rel,
                    _find_line(lines, f'"{name}"'),
                    f'"{name}": "{spec}"',
                    str(name),
                    "Packagist",
                    version,
                    pinned,
                )

    def _parse_csproj(self, inventory: Inventory, path: Path, rel: str) -> None:
        raw = path.read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()
        for match in _RE_CSPROJ.finditer(raw):
            name, version = match.group(1), match.group(2)
            self._emit(
                inventory,
                rel,
                _find_line(lines, name),
                match.group(0)[:200],
                name,
                "NuGet",
                version,
                bool(version),
            )

    # -- pep508 helpers --------------------------------------------------------

    def _emit_pep508(self, inventory: Inventory, rel: str, lines: list[str], spec: str) -> None:
        nm = _RE_PEP508_NAME.match(spec)
        if not nm:
            return
        version, pinned = _pep508_version(spec)
        self._emit(
            inventory,
            rel,
            _find_line(lines, nm.group(1)),
            spec,
            nm.group(1),
            "PyPI",
            version,
            pinned,
        )

    def _emit_named(
        self,
        inventory: Inventory,
        rel: str,
        lines: list[str],
        name: str,
        ver: tuple[str | None, bool],
    ) -> None:
        version, pinned = ver
        self._emit(inventory, rel, _find_line(lines, name), name, name, "PyPI", version, pinned)


def _pep508_version(spec: str) -> tuple[str | None, bool]:
    pin = _RE_PIN.search(spec)
    if pin:
        return pin.group(1), True
    rng = _RE_RANGE.search(spec)
    return (rng.group(1), False) if rng else (None, False)


def _spec_version(spec: object) -> tuple[str | None, bool]:
    """Version from a Poetry/Pipfile value (a string like '^1.2' or a table)."""
    if isinstance(spec, dict):
        spec = spec.get("version", "")
    text = str(spec).strip()
    if text in {"*", ""}:
        return None, False
    if re.fullmatch(r"""==?\s*[0-9][^,\s]*""", text):
        return text.lstrip("= "), True
    rng = _RE_RANGE.search(text)
    if rng:
        return rng.group(1), False
    if re.fullmatch(r"""[0-9][A-Za-z0-9._-]*""", text):
        return text, True
    return None, False


def _npm_version(spec: str) -> tuple[str | None, bool]:
    text = spec.strip()
    if re.fullmatch(r"""\d+\.\d+\.\d+""", text):
        return text, True
    m = re.search(r"""(\d+\.\d+(?:\.\d+)?)""", text)
    return (m.group(1), False) if m else (None, False)


def _cargo_version(spec: Any) -> tuple[str | None, bool]:
    """Cargo deps are either "1.2.3" or a table with a version key."""
    raw = str(spec.get("version", "") or "") if isinstance(spec, dict) else str(spec)
    text = raw.strip()
    if not text:
        return None, False
    # A bare "1.2.3" in Cargo means "^1.2.3", so it is not an exact pin;
    # "=1.2.3" is.
    if text.startswith("="):
        exact = text[1:].strip()
        return (exact, True) if exact else (None, False)
    match = re.search(r"""(\d+(?:\.\d+){0,2})""", text)
    return (match.group(1), False) if match else (None, False)


def _gem_version(constraint: str | None) -> tuple[str | None, bool]:
    """Gemfile: a bare "1.2.3" pins; "~> 1.2" and ">= 1.2" do not."""
    if not constraint:
        return None, False
    text = constraint.strip()
    if re.fullmatch(r"""\d+(?:\.\d+){0,2}""", text):
        return text, True
    match = re.search(r"""(\d+(?:\.\d+){0,2})""", text)
    return (match.group(1), False) if match else (None, False)


def _resolve_maven_version(version: str, properties: dict[str, str]) -> str:
    """Expand a single ${property} indirection; leave anything else alone."""
    text = version.strip()
    match = re.fullmatch(r"""\$\{([^}]+)\}""", text)
    if match:
        return properties.get(match.group(1), "").strip()
    return text


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 1
