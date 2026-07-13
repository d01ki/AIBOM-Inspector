"""RepoCollector — static discovery of AI usage in a source tree.

Detects model references, datasets, prompts, agents, and external AI services by
pattern-matching source files. It never imports, executes, or otherwise runs the
scanned code; it only reads text.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from aibom.collectors.base import Collector
from aibom.inventory import Inventory
from aibom.models.entities import (
    Agent,
    Dataset,
    Entity,
    Model,
    Prompt,
    Relationship,
    RelationshipType,
    Service,
)
from aibom.models.evidence import Evidence
from aibom.models.signals import RiskSignal

# Directories that never contain first-party AI supply-chain signal worth scanning.
_IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist", "build",
    "site-packages", ".idea", ".vscode", ".next", ".cache",
}

# Text files worth reading line-by-line.
_TEXT_SUFFIXES = {
    ".py", ".txt", ".md", ".rst", ".json", ".yaml", ".yml", ".toml", ".cfg",
    ".ini", ".jinja", ".jinja2", ".j2", ".prompt", ".sh", ".env",
    ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".ipynb",
}
_TEXT_NAMES = {"dockerfile", "requirements.txt", "pipfile", ".env"}

# Serialized-model weight formats, by extension. Value = confidence.
_WEIGHT_SUFFIXES: dict[str, float] = {
    ".safetensors": 0.95, ".gguf": 0.95, ".onnx": 0.9, ".h5": 0.85,
    ".pt": 0.85, ".pth": 0.85, ".ckpt": 0.85, ".pkl": 0.9, ".pickle": 0.9,
    ".msgpack": 0.8, ".bin": 0.5, ".pb": 0.6,
}

_MAX_FILE_BYTES = 2_000_000

# ── line-level detectors (regex applied per source line) ─────────────────────

_RE_FROM_PRETRAINED_CALL = re.compile(r"""\bfrom_pretrained\s*\(""")
_RE_STRING = re.compile(r"""['"]([^'"]+)['"]""")
_RE_PIPELINE_MODEL = re.compile(r"""model\s*=\s*['"]([A-Za-z0-9._\-/]+/[A-Za-z0-9._\-]+)['"]""")
_RE_HF_URL = re.compile(r"""huggingface\.co/([A-Za-z0-9][\w\-.]*/[\w\-.]+)""")
_RE_REPO_ID = re.compile(r"""repo_id\s*=\s*['"]([^'"]+)['"]""")
_RE_REVISION = re.compile(r"""revision\s*=\s*['"]([^'"]+)['"]""")
_RE_LOAD_DATASET = re.compile(r"""load_dataset\(\s*['"]([^'"]+)['"]""")
_RE_LLM_MODEL = re.compile(
    r"""['"]((?:gpt-|o1|o3|o4|chatgpt-|claude-)[A-Za-z0-9._\-]+)['"]"""
)
# A SYSTEM-ish variable assigned a *string literal* — the hardcoded-prompt shape.
# Requiring the string RHS avoids matching expressions like ``= re.compile(...)``.
_RE_SYSTEM_PROMPT_VAR = re.compile(
    r"""^\s*(?:[A-Z_]*SYSTEM[A-Z_]*(?:PROMPT|MESSAGE)?|system_prompt|system_message)"""
    r"""\s*=\s*[rbfRBF]{0,2}['"]"""
)
_RE_ROLE_SYSTEM = re.compile(r"""["']role["']\s*:\s*["']system["']""")
_RE_BASE_URL = re.compile(r"""base_url\s*=\s*['"](https?://[^'"]+)['"]""")
# Require a call ``ctor(`` — matches real agent construction, not bare mentions of
# the name in prose, imports, or regex/string literals (precision over recall).
_RE_AGENT_CTOR = re.compile(
    r"""\b(initialize_agent|create_react_agent|create_tool_calling_agent"""
    r"""|create_openai_functions_agent|create_openai_tools_agent|AgentExecutor)\s*\("""
)
_RE_TRUST_REMOTE = re.compile(r"""trust_remote_code\s*=\s*True""")

# An mcpServers entry used as a JSON/dict key — an actual MCP config, not a mention.
_RE_MCP = re.compile(r"""['"]mcpServers['"]\s*:""")

# MCP *server* implementations (the supply-chain surface an AI client consumes):
# Python mcp / fastmcp usage, or the TS server SDK.
_RE_MCP_SERVER_PY = re.compile(
    r"""(?:^\s*from\s+(?:mcp|fastmcp)(?:[.\w]*)\s+import\b"""
    r"""|^\s*import\s+(?:mcp|fastmcp)\b"""
    r"""|\bFastMCP\s*\()"""
)
_RE_MCP_SERVER_JS = re.compile(
    r"""(?:from\s*|require\s*\(\s*)['"]@modelcontextprotocol/(?:sdk|server)[^'"]*['"]"""
)

# JS/TS provider SDK imports (ESM import-from or CJS require of an AI SDK).
_JS_PROVIDER_IMPORTS: dict[str, tuple[str, str | None]] = {
    "openai": ("openai", "https://api.openai.com"),
    "@anthropic-ai/sdk": ("anthropic", "https://api.anthropic.com"),
    "@google/generative-ai": ("google", "https://generativelanguage.googleapis.com"),
    "@google/genai": ("google", "https://generativelanguage.googleapis.com"),
    "cohere-ai": ("cohere", "https://api.cohere.ai"),
    "@mistralai/mistralai": ("mistral", "https://api.mistral.ai"),
    "groq-sdk": ("groq", "https://api.groq.com"),
    "ollama": ("ollama", "http://localhost:11434"),
}
_RE_JS_IMPORT = re.compile(
    r"""(?:import\s[^;]*?from\s*|import\s*|require\s*\(\s*)['"]("""
    + "|".join(re.escape(k) for k in _JS_PROVIDER_IMPORTS)
    + r""")['"]"""
)

# Hardcoded-secret heuristics. A provider key with a recognizable prefix, or an
# assignment of a secret-ish name to a literal string that is *not* an env
# lookup / obvious placeholder.
_RE_PROVIDER_KEY = re.compile(r"""\b(sk-ant-[A-Za-z0-9\-_]{16,}|sk-[A-Za-z0-9]{20,})\b""")
_RE_SECRET_ASSIGN = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret|token|password|access[_-]?key)\s*[:=]\s*"""
    r"""['"]([^'"]{8,})['"]"""
)
_RE_ENV_OR_PLACEHOLDER = re.compile(
    r"""(?i)(os\.environ|getenv|your[_-]|<[^>]+>|\{\{|\$\{|xxx+|changeme|example|placeholder|\.\.\.)"""
)

# import <-> provider service mapping
_PROVIDER_IMPORTS = {
    "openai": ("openai", "https://api.openai.com"),
    "anthropic": ("anthropic", "https://api.anthropic.com"),
    "cohere": ("cohere", "https://api.cohere.ai"),
    "mistralai": ("mistral", "https://api.mistral.ai"),
}


def _looks_like_hf_repo(name: str) -> bool:
    """Heuristic: 'org/model' shape, not a local filesystem path."""
    return "/" in name and not name.startswith((".", "/", "~")) and " " not in name


def _call_args(text: str, open_paren_idx: int) -> str | None:
    """Return the substring inside a balanced ``(...)`` starting at ``open_paren_idx``.

    Skips string literals so parentheses/quotes inside strings do not confuse
    depth tracking. Returns ``None`` if the parentheses are unbalanced.
    """
    depth = 0
    quote: str | None = None
    i = open_paren_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_idx + 1 : i]
        i += 1
    return None


def _model_provider(name: str) -> str:
    """Classify a model reference as a remote HF repo or a local path."""
    if name.startswith((".", "/", "~")) or "\\" in name:
        return "local"
    if name.lower().endswith(tuple(_WEIGHT_SUFFIXES)):
        return "local"
    return "huggingface"


class RepoCollector(Collector):
    """Scan a repository/local directory for AI supply-chain components."""

    name = "repo"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"scan target does not exist: {self.root}")

    # -- public API ------------------------------------------------------------

    def collect(self, inventory: Inventory) -> None:
        for path in self._iter_files():
            rel = self._rel(path)
            suffix = path.suffix.lower()
            if suffix in _WEIGHT_SUFFIXES:
                self._detect_weight_file(inventory, path, rel)
            if self._is_text_file(path):
                self._scan_text_file(inventory, path, rel)

    # -- file iteration --------------------------------------------------------

    def _iter_files(self) -> list[Path]:
        if self.root.is_file():
            return [self.root]
        files: list[Path] = []
        for path in self.root.rglob("*"):
            if path.is_dir():
                continue
            if any(part in _IGNORE_DIRS for part in path.parts):
                continue
            files.append(path)
        return sorted(files)

    def _rel(self, path: Path) -> str:
        try:
            base = self.root if self.root.is_dir() else self.root.parent
            return path.relative_to(base).as_posix()
        except ValueError:
            return path.as_posix()

    @staticmethod
    def _is_text_file(path: Path) -> bool:
        if path.suffix.lower() in _TEXT_SUFFIXES:
            return True
        return path.name.lower() in _TEXT_NAMES

    # -- weight-file detector --------------------------------------------------

    def _detect_weight_file(self, inventory: Inventory, path: Path, rel: str) -> None:
        suffix = path.suffix.lower()
        fmt = suffix.lstrip(".")
        ev = Evidence(
            file=rel,
            line_start=1,
            line_end=1,
            snippet=path.name,
            matched_pattern="weight-file-extension",
            confidence=_WEIGHT_SUFFIXES[suffix],
        )
        inventory.add_entity(
            Model(name=rel, provider="local", formats=[fmt], source_evidence=[ev])
        )

    # -- text scanner ----------------------------------------------------------

    def _scan_text_file(self, inventory: Inventory, path: Path, rel: str) -> None:
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                return
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        # Notebooks are JSON with the code escaped; unescape quotes so the
        # detectors see the code as written (line numbers are unaffected).
        if path.suffix.lower() == ".ipynb":
            text = text.replace('\\"', '"')

        lines = text.splitlines()
        # per-file buckets used to draw intra-file relationship edges
        buckets: dict[type[Entity], list[str]] = defaultdict(list)

        # Whole-file prompt template? (prompts/ dir or template-ish extension)
        if self._is_prompt_template(path):
            ent = self._make_template_prompt(text, rel)
            buckets[Prompt].append(inventory.add_entity(ent).id)

        # Multiline-aware detectors (e.g. from_pretrained calls spanning lines).
        for entity in self._scan_calls(text, lines, rel):
            canonical = inventory.add_entity(entity)
            buckets[type(canonical)].append(canonical.id)

        for lineno, line in enumerate(lines, start=1):
            for entity in self._scan_line(line, lineno, rel):
                canonical = inventory.add_entity(entity)
                buckets[type(canonical)].append(canonical.id)
            self._scan_signals(inventory, line, lineno, rel)

        self._link_intra_file(inventory, buckets)

    def _scan_signals(self, inventory: Inventory, line: str, lineno: int, rel: str) -> None:
        """Detect non-entity risk signals (trust_remote_code, hardcoded secrets)."""

        def signal(kind: str, pattern: str, conf: float, detail: str | None = None) -> None:
            inventory.add_signal(
                RiskSignal(
                    kind=kind,
                    detail=detail,
                    source_evidence=[
                        Evidence(
                            file=rel, line_start=lineno, line_end=lineno,
                            snippet=line.strip()[:200], matched_pattern=pattern, confidence=conf,
                        )
                    ],
                )
            )

        if _RE_TRUST_REMOTE.search(line):
            signal("trust_remote_code", "trust_remote_code=True", 0.95)

        if _RE_ENV_OR_PLACEHOLDER.search(line):
            return  # env lookup / placeholder — not a hardcoded secret
        if _RE_PROVIDER_KEY.search(line):
            signal("hardcoded_secret", "provider-key-literal", 0.9, "provider API key literal")
        elif _RE_SECRET_ASSIGN.search(line):
            signal("hardcoded_secret", "secret-assignment", 0.6, "secret assigned a string literal")

    def _scan_line(self, line: str, lineno: int, rel: str) -> list[Entity]:
        found: list[Entity] = []

        def ev(pattern: str, snippet: str, conf: float) -> Evidence:
            return Evidence(
                file=rel, line_start=lineno, line_end=lineno,
                snippet=snippet.strip()[:200], matched_pattern=pattern, confidence=conf,
            )

        revision_match = _RE_REVISION.search(line)
        revision = revision_match.group(1) if revision_match else None

        # models — repo_id / pipeline(model=) / HF url (from_pretrained is multiline)
        for pat, regex, conf in (
            ("repo_id", _RE_REPO_ID, 0.85),
            ("pipeline-model", _RE_PIPELINE_MODEL, 0.9),
        ):
            for m in regex.finditer(line):
                name = m.group(1)
                if not _looks_like_hf_repo(name):
                    continue
                found.append(
                    Model(
                        name=name, provider=_model_provider(name), revision=revision,
                        revision_pinned=revision is not None, source_evidence=[ev(pat, line, conf)],
                    )
                )
        for m in _RE_HF_URL.finditer(line):
            found.append(
                Model(name=m.group(1), provider="huggingface",
                      source_evidence=[ev("hf-url", line, 0.9)])
            )
        for m in _RE_LLM_MODEL.finditer(line):
            name = m.group(1)
            provider = "anthropic" if name.startswith("claude-") else "openai"
            found.append(
                Model(name=name, provider=provider, source_evidence=[ev("llm-model-id", line, 0.7)])
            )

        # datasets
        for m in _RE_LOAD_DATASET.finditer(line):
            found.append(
                Dataset(name=m.group(1), source="huggingface",
                        source_evidence=[ev("load_dataset", line, 0.9)])
            )

        # prompts — hardcoded system prompt
        if _RE_SYSTEM_PROMPT_VAR.search(line) or _RE_ROLE_SYSTEM.search(line):
            found.append(
                Prompt(
                    name=f"system-prompt@{rel}:{lineno}", kind="system",
                    content_hash=_sha(line), source_evidence=[ev("system-prompt", line, 0.7)],
                )
            )

        # services — provider SDK imports, explicit base_url, MCP
        for key, (svc_name, endpoint) in _PROVIDER_IMPORTS.items():
            if re.search(rf"""^\s*(?:import|from)\s+{re.escape(key)}\b""", line):
                found.append(
                    Service(name=svc_name, kind="api", endpoint=endpoint,
                            source_evidence=[ev("provider-import", line, 0.6)])
                )
        for m in _RE_BASE_URL.finditer(line):
            found.append(
                Service(name=m.group(1), kind="api", endpoint=m.group(1),
                        source_evidence=[ev("base-url", line, 0.7)])
            )
        if _RE_MCP.search(line):
            found.append(
                Service(name=f"mcp-config@{rel}", kind="mcp",
                        source_evidence=[ev("mcp-config", line, 0.8)])
            )
        if _RE_MCP_SERVER_PY.search(line) or _RE_MCP_SERVER_JS.search(line):
            found.append(
                Service(name=f"mcp-server@{rel}", kind="mcp",
                        source_evidence=[ev("mcp-server", line, 0.85)])
            )
        for m in _RE_JS_IMPORT.finditer(line):
            js_svc, js_endpoint = _JS_PROVIDER_IMPORTS[m.group(1)]
            found.append(
                Service(name=js_svc, kind="api", endpoint=js_endpoint,
                        source_evidence=[ev("provider-import-js", line, 0.6)])
            )

        # agents (ignore import statements — those are dependencies, not constructions)
        is_import = bool(re.match(r"""^\s*(?:import|from)\s""", line))
        for m in () if is_import else _RE_AGENT_CTOR.finditer(line):
            found.append(
                Agent(name=f"agent@{rel}:{lineno}", framework="langchain",
                      source_evidence=[ev(f"agent-ctor:{m.group(1)}", line, 0.8)])
            )

        return found

    def _scan_calls(self, text: str, lines: list[str], rel: str) -> list[Entity]:
        """Detect ``from_pretrained(...)`` calls, including those spanning lines."""
        found: list[Entity] = []
        for m in _RE_FROM_PRETRAINED_CALL.finditer(text):
            args = _call_args(text, m.end() - 1)
            if args is None:
                continue
            name_match = _RE_STRING.search(args)
            if name_match is None:
                continue
            name = name_match.group(1)
            rev_match = _RE_REVISION.search(args)
            revision = rev_match.group(1) if rev_match else None
            lineno = text.count("\n", 0, m.start()) + 1
            snippet = lines[lineno - 1].strip() if lineno - 1 < len(lines) else name
            found.append(
                Model(
                    name=name,
                    provider=_model_provider(name),
                    revision=revision,
                    revision_pinned=revision is not None,
                    source_evidence=[
                        Evidence(
                            file=rel, line_start=lineno, line_end=lineno,
                            snippet=snippet[:200], matched_pattern="from_pretrained",
                            confidence=0.95,
                        )
                    ],
                )
            )
        return found

    # -- prompt templates ------------------------------------------------------

    @staticmethod
    def _is_prompt_template(path: Path) -> bool:
        if path.suffix.lower() in {".jinja", ".jinja2", ".j2", ".prompt"}:
            return True
        parts_lower = {p.lower() for p in path.parts}
        return bool({"prompts", "prompt"} & parts_lower) and path.suffix.lower() in {".txt", ".md"}

    @staticmethod
    def _make_template_prompt(text: str, rel: str) -> Prompt:
        n_lines = max(len(text.splitlines()), 1)
        ev = Evidence(
            file=rel, line_start=1, line_end=n_lines, snippet=text.strip()[:200],
            matched_pattern="prompt-template-file", confidence=0.85,
        )
        return Prompt(name=rel, kind="template", content_hash=_sha(text), source_evidence=[ev])

    # -- relationships ---------------------------------------------------------

    @staticmethod
    def _link_intra_file(inventory: Inventory, buckets: dict[type[Entity], list[str]]) -> None:
        """Link agents to co-located models, prompts, and services (file scope)."""
        agents = buckets.get(Agent, [])
        if not agents:
            return
        edges = (
            (Model, RelationshipType.INVOKES),
            (Prompt, RelationshipType.USES_PROMPT),
            (Service, RelationshipType.INVOKES),
        )
        for agent_id in agents:
            for entity_cls, rel_type in edges:
                for target_id in buckets.get(entity_cls, []):
                    inventory.add_relationship(
                        Relationship(
                            source_id=agent_id, target_id=target_id, relationship=rel_type,
                            source_evidence=[
                                Evidence(
                                    file="<inferred>", line_start=1, line_end=1,
                                    snippet="agent and target co-located in file",
                                    matched_pattern="intra-file-colocation", confidence=0.5,
                                )
                            ],
                        )
                    )


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
