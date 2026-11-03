"""Component linker — evidence-backed edges between AI components and packages.

Detectors find models, services and datasets in source; collectors find the
packages a manifest or lockfile declares. Without a link between the two, the
dependency map shows a model and the SDK that calls it as unrelated islands.
This module draws two kinds of edge, and only when the scanned files prove it:

``model --served_by--> service``
    The model's provider (attributed by its detector at a cited line) names an
    API service the scan also found, e.g. ``gpt-4o-mini`` -> ``openai``.

``component --depends_on--> package``
    A file that evidences the component imports the package (the import line is
    the edge's evidence), *and* the package belongs to the component's provider
    family, so ``gpt-4o-mini`` in a file importing both ``openai`` and
    ``transformers`` links only to ``openai``.

Anything that cannot be shown this way is left unlinked rather than guessed.
Files are read as text, bounded in size, and never executed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from aibom.inventory import Inventory
from aibom.models.entities import (
    Dataset,
    Entity,
    Model,
    Package,
    Relationship,
    RelationshipType,
    Service,
)
from aibom.models.evidence import Evidence

DETECTOR_ID = "linker.components"
_MAX_BYTES = 1_000_000

# Provider family tokens. A package belongs to a provider when its name contains
# one of these tokens; the table is deliberately small and reviewable.
_PROVIDER_TOKENS: dict[str, tuple[str, ...]] = {
    "openai": ("openai",),
    "anthropic": ("anthropic",),
    "huggingface": (
        "huggingface",
        "transformers",
        "diffusers",
        "sentence-transformers",
        "sentence_transformers",
        "@huggingface/",
    ),
    "google": ("google-genai", "google-generativeai", "@google/genai", "@google/generative-ai"),
    "cohere": ("cohere",),
    "mistral": ("mistral",),
    "groq": ("groq",),
    "ollama": ("ollama",),
    "vercel-ai-gateway": ("@ai-sdk/gateway",),
}

# Packages whose provider is not spelled in their name.
_PROVIDER_OVERRIDES: dict[tuple[str, str], str] = {
    ("pypi", "datasets"): "huggingface",
    ("pypi", "openai-agents"): "openai",
    ("npm", "@openai/agents"): "openai",
    # The AI SDK core package exports `gateway`; the gateway service is only
    # detected at a gateway call, so the import still has to be in that file.
    ("npm", "ai"): "vercel-ai-gateway",
}

# Packages that load datasets only, and hub clients that load either kind.
_DATASET_PACKAGES = {("pypi", "datasets")}
_HUB_PACKAGES = {("pypi", "huggingface-hub"), ("pypi", "huggingface_hub")}

# PyPI distribution -> importable module, where the default (lowercase, '-' to
# '_') is wrong.
_PYPI_MODULES: dict[str, str] = {
    "openai-agents": "agents",
    "google-genai": "google.genai",
    "google-generativeai": "google.generativeai",
    "huggingface-hub": "huggingface_hub",
    "mistralai": "mistralai",
}

_SOURCE_ECOSYSTEM = {
    ".py": "pypi",
    ".ipynb": "pypi",
    ".js": "npm",
    ".jsx": "npm",
    ".mjs": "npm",
    ".cjs": "npm",
    ".ts": "npm",
    ".tsx": "npm",
    ".mts": "npm",
    ".cts": "npm",
    ".go": "go",
    ".rs": "crates.io",
    ".java": "maven",
    ".kt": "maven",
    ".cs": "nuget",
}


def link_components(inventory: Inventory, root: str | Path) -> None:
    """Add evidence-backed AI component edges to ``inventory`` in place."""
    base = Path(root).resolve()
    if base.is_file():
        base = base.parent
    if DETECTOR_ID not in inventory.stats.detectors_run:
        inventory.stats.detectors_run.append(DETECTOR_ID)

    services = {
        e.name.strip().lower(): e
        for e in inventory.entities
        if isinstance(e, Service) and e.kind == "api"
    }
    for model in (e for e in inventory.entities if isinstance(e, Model)):
        _link_model_to_service(inventory, model, services)

    packages = [e for e in inventory.entities if isinstance(e, Package) and e.ai]
    if not packages:
        return
    reader = _SourceReader(base)
    for component in inventory.entities:
        provider = _provider_of(component)
        if provider is None:
            continue
        candidates = [
            p
            for p in packages
            if _package_provider(p) == provider
            and _serves_kind(p, isinstance(component, Dataset))
        ]
        if candidates:
            _link_component_to_packages(inventory, component, candidates, reader)


def _provider_of(entity: Entity) -> str | None:
    if isinstance(entity, Model):
        value = entity.provider
    elif isinstance(entity, Service):
        value = entity.name if entity.kind == "api" else None
    elif isinstance(entity, Dataset):
        value = entity.source
    else:
        return None
    if not value:
        return None
    value = value.strip().lower()
    return value if value in _PROVIDER_TOKENS else None


def _serves_kind(package: Package, dataset: bool) -> bool:
    """Dataset loaders link to datasets only, and model libraries to the rest.

    One file commonly imports both ``datasets`` and ``transformers``; without
    this split every model there would claim to depend on the dataset loader.
    """
    key = ((package.ecosystem or "").lower(), package.name.strip().lower())
    if key in _DATASET_PACKAGES:
        return dataset
    return not dataset or key in _HUB_PACKAGES


def _package_provider(package: Package) -> str | None:
    eco = (package.ecosystem or "").lower()
    name = package.name.strip().lower()
    override = _PROVIDER_OVERRIDES.get((eco, name))
    if override:
        return override
    for provider, tokens in _PROVIDER_TOKENS.items():
        if any(token in name for token in tokens):
            return provider
    return None


def _link_model_to_service(
    inventory: Inventory, model: Model, services: dict[str, Service]
) -> None:
    provider = (model.provider or "").strip().lower()
    service = services.get(provider)
    if service is None or not model.source_evidence:
        return
    cited = model.source_evidence[0]
    inventory.add_relationship(
        Relationship(
            source_id=model.id,
            target_id=service.id,
            relationship=RelationshipType.SERVED_BY,
            source_evidence=[
                Evidence(
                    file=cited.file,
                    line_start=cited.line_start,
                    line_end=cited.line_end,
                    snippet=f"model provider attributed as {provider} ({cited.matched_pattern})",
                    matched_pattern="model-provider-service",
                    confidence=min(cited.confidence, 0.9),
                    detector_id=DETECTOR_ID,
                    kind="link",
                )
            ],
        )
    )


def _link_component_to_packages(
    inventory: Inventory,
    component: Entity,
    packages: list[Package],
    reader: _SourceReader,
) -> None:
    files = dict.fromkeys(ev.file for ev in component.source_evidence)
    for package in packages:
        pattern = _import_pattern(package)
        if pattern is None:
            continue
        for rel in files:
            if _SOURCE_ECOSYSTEM.get(Path(rel).suffix.lower()) != (package.ecosystem or "").lower():
                continue
            hit = reader.find(rel, pattern)
            if hit is None:
                continue
            lineno, line = hit
            inventory.add_relationship(
                Relationship(
                    source_id=component.id,
                    target_id=package.id,
                    relationship=RelationshipType.DEPENDS_ON,
                    source_evidence=[
                        Evidence(
                            file=rel,
                            line_start=lineno,
                            line_end=lineno,
                            snippet=line.strip()[:200],
                            matched_pattern="component-package-import",
                            confidence=0.85,
                            detector_id=DETECTOR_ID,
                            kind="link",
                        )
                    ],
                )
            )
            break


def _import_pattern(package: Package) -> re.Pattern[str] | None:
    """A regex matching a source line that imports ``package``."""
    eco = (package.ecosystem or "").lower()
    name = package.name.strip()
    if eco == "pypi":
        module = _PYPI_MODULES.get(name.lower(), name.lower().replace("-", "_"))
        mod = re.escape(module)
        # An optional leading quote admits notebook JSON source lines.
        return re.compile(rf"^\s*\"?(?:from\s+{mod}(?:\.\w+)*\s+import\b|import\s+{mod}\b)")
    if eco == "npm":
        spec = re.escape(name)
        return re.compile(
            rf"""(?:\bfrom\s+|\bimport\s+|\brequire\(\s*|\bimport\(\s*)['"]{spec}(?:/[^'"]*)?['"]"""
        )
    if eco == "go":
        module = re.escape(re.sub(r"/v[0-9]+$", "", name))
        return re.compile(rf'"{module}(?:/v[0-9]+)?(?:/[^"]*)?"')
    if eco == "crates.io":
        crate = re.escape(name.replace("-", "_"))
        return re.compile(rf"^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+{crate}\b")
    if eco == "maven" and ":" in name:
        group = re.escape(name.split(":", 1)[0])
        return re.compile(rf"^\s*import\s+(?:static\s+)?{group}\.")
    if eco == "nuget":
        return re.compile(rf"^\s*using\s+{re.escape(name)}\s*[;.]")
    return None


class _SourceReader:
    """Bounded, cached, read-only access to scanned files by repo-relative path."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, rel: str) -> list[str] | None:
        if rel not in self._cache:
            self._cache[rel] = self._read(rel)
        return self._cache[rel]

    def _read(self, rel: str) -> list[str] | None:
        path = (self.base / rel).resolve()
        try:
            path.relative_to(self.base)
        except ValueError:
            return None
        try:
            if not path.is_file() or path.stat().st_size > _MAX_BYTES:
                return None
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        if path.suffix.lower() == ".ipynb":
            # Same unescape as the repo collector, so line numbers agree.
            text = text.replace('\\"', '"')
        return text.splitlines()

    def find(self, rel: str, pattern: re.Pattern[str]) -> tuple[int, str] | None:
        return _first_match(self.lines(rel) or [], pattern)


def _first_match(lines: Iterable[str], pattern: re.Pattern[str]) -> tuple[int, str] | None:
    for lineno, line in enumerate(lines, 1):
        if pattern.search(line):
            return lineno, line
    return None
