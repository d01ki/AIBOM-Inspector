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
from aibom.inventory import Inventory
from aibom.models.entities import Package
from aibom.models.evidence import Evidence

_IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "dist", "build", "site-packages",
}

# AI/ML ecosystem allowlist (normalized: lowercase, '_' -> '-'). Kept curated so
# the AIBOM stays AI-focused rather than becoming a general SBOM.
_AI_PYPI = {
    "transformers", "torch", "torchvision", "torchaudio", "tensorflow", "keras",
    "jax", "jaxlib", "flax", "openai", "anthropic", "cohere", "mistralai",
    "google-generativeai", "google-genai", "litellm", "langgraph", "llama-index",
    "llama-cpp-python", "ctransformers", "vllm", "sglang", "text-generation",
    "sentence-transformers", "diffusers", "accelerate", "datasets",
    "huggingface-hub", "tokenizers", "safetensors", "ollama", "guidance",
    "instructor", "autogen", "autogenstudio", "pyautogen", "crewai", "haystack-ai",
    "onnxruntime", "onnx", "optimum", "timm", "peft", "trl", "bitsandbytes",
    "sentencepiece", "gpt4all", "openai-whisper", "spacy", "scikit-learn",
    "xgboost", "lightgbm", "catboost", "replicate", "groq", "instructorai",
    "mcp", "fastmcp", "modelcontextprotocol",
}
_AI_PYPI_PREFIXES = ("langchain", "llama-index", "llamaindex", "llama-cpp")

_AI_NPM = {
    "openai", "@anthropic-ai/sdk", "@google/generative-ai", "@google/genai",
    "cohere-ai", "@mistralai/mistralai", "ai", "langchain", "llamaindex",
    "ollama", "replicate", "groq-sdk", "openai-edge", "fastmcp",
}
_AI_NPM_PREFIXES = ("@langchain/", "@llamaindex/", "@huggingface/", "@ai-sdk/",
                    "@anthropic-ai/", "@modelcontextprotocol/")

_RE_REQ = re.compile(
    r"""^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"""
    r"""(?:(===|==|~=|>=|<=|!=|>|<)\s*([A-Za-z0-9][A-Za-z0-9._*+!-]*))?"""
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


class DependencyCollector(Collector):
    """Scan dependency manifests for AI/ML packages."""

    name = "dependencies"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def collect(self, inventory: Inventory) -> None:
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
            if path.is_dir() or any(p in _IGNORE_DIRS for p in path.parts):
                continue
            n = path.name.lower()
            if (
                (n.startswith("requirements") and n.endswith(".txt"))
                or n in {"pyproject.toml", "pipfile", "package.json"}
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
        self, inventory: Inventory, rel: str, lineno: int, snippet: str,
        name: str, ecosystem: str, version: str | None, pinned: bool,
    ) -> None:
        ai = _is_ai_pypi(name) if ecosystem == "PyPI" else _is_ai_npm(name)
        ev = Evidence(
            file=rel, line_start=lineno, line_end=lineno, snippet=snippet.strip()[:200],
            matched_pattern=f"{ecosystem.lower()}-dependency", confidence=0.9,
        )
        inventory.add_entity(
            Package(
                name=name, ecosystem=ecosystem, version=version,
                version_pinned=pinned, ai=ai, source_evidence=[ev],
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
            self._emit(inventory, rel, lineno, line, m.group(1), "PyPI",
                       ver if op else None, pinned)

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
                self._emit(inventory, rel, _find_line(lines, f'"{name}"'), f'"{name}": "{spec}"',
                           name, "npm", version, pinned)

    # -- pep508 helpers --------------------------------------------------------

    def _emit_pep508(self, inventory: Inventory, rel: str, lines: list[str], spec: str) -> None:
        nm = _RE_PEP508_NAME.match(spec)
        if not nm:
            return
        version, pinned = _pep508_version(spec)
        self._emit(inventory, rel, _find_line(lines, nm.group(1)), spec,
                   nm.group(1), "PyPI", version, pinned)

    def _emit_named(
        self, inventory: Inventory, rel: str, lines: list[str], name: str,
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


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 1
