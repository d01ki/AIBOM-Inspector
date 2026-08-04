"""LockfileCollector — resolved dependencies, artifact digests, and registries.

A manifest states what a project *asks for*; a lockfile states what it actually
gets. That difference is exactly what the 2026 CISA SBOM minimum elements ask
for and what a manifest cannot supply:

* **Coverage** — transitive dependencies, not just the top level;
* **Component Version** — the resolved pin, not a range;
* **Component Hash** + **Component Hash Algorithm** — the artifact digest the
  package manager verified on install;
* **Component Producer** — the registry that supplied the artifact.

Supported lockfiles: ``package-lock.json`` (npm), ``Pipfile.lock``,
``poetry.lock``, ``uv.lock``, hash-pinned ``requirements*.txt`` (PyPI),
``Cargo.lock`` (crates.io), ``composer.lock`` (Packagist) and ``Gemfile.lock``
(RubyGems). Everything is parsed as text — nothing is installed or executed.

Entities merge into the ones the :class:`~aibom.collectors.dependencies.
DependencyCollector` already emitted (same natural key), so a package declared
in a manifest *and* resolved in a lockfile stays one component that now carries
its digest.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any

from aibom.collectors.base import Collector
from aibom.collectors.dependencies import _IGNORE_DIRS, _is_ai_package, _load_toml
from aibom.detectors.python.parser import classify_source_context
from aibom.inventory import Inventory
from aibom.models.analysis import ConfidenceFactors, UsageState
from aibom.models.entities import DependencyScope, Package
from aibom.models.evidence import Evidence

DETECTOR_ID = "lockfile.dependencies"

_LOCKFILE_NAMES = {
    "package-lock.json",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
}

# Digest length (hex chars) -> CycloneDX hash algorithm name. Used when a
# lockfile records a bare digest without naming its algorithm.
_ALG_BY_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}

# Algorithm label as lockfiles spell it -> CycloneDX enum value.
_ALG_NAMES = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}

_RE_TOML_NAME = re.compile(r'^\s*name\s*=\s*["\']([^"\']+)["\']')
_RE_NPM_PATH = re.compile(r'^\s*"((?:[^"]*/)?node_modules/[^"]+)"\s*:')
_RE_JSON_KEY = re.compile(r'^\s*"([^"]+)"\s*:')
_RE_JSON_NAME = re.compile(r'^\s*"name"\s*:\s*"([^"]+)"')
_RE_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$")
_RE_GEM_DIRECT = re.compile(r"^ {2}([A-Za-z0-9_.\-]+)")
_RE_REQ_HASH = re.compile(r"--hash=([A-Za-z0-9]+):([A-Fa-f0-9]+)")
_RE_REQ_PIN = re.compile(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")


class LockfileCollector(Collector):
    """Inventory every resolved dependency, with its digest and registry."""

    name = "lockfiles"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def collect(self, inventory: Inventory) -> None:
        if DETECTOR_ID not in inventory.stats.detectors_run:
            inventory.stats.detectors_run.append(DETECTOR_ID)
        for path in self._iter_lockfiles():
            rel = self._rel(path)
            name = path.name.lower()
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                if name == "package-lock.json":
                    self._parse_package_lock(inventory, text, rel)
                elif name == "pipfile.lock":
                    self._parse_pipfile_lock(inventory, text, rel)
                elif name == "poetry.lock":
                    self._parse_poetry_lock(inventory, text, rel)
                elif name == "uv.lock":
                    self._parse_uv_lock(inventory, text, rel)
                elif name == "cargo.lock":
                    self._parse_cargo_lock(inventory, text, rel)
                elif name == "composer.lock":
                    self._parse_composer_lock(inventory, text, rel)
                elif name == "gemfile.lock":
                    self._parse_gemfile_lock(inventory, text, rel)
                elif name.startswith("requirements") and name.endswith(".txt"):
                    self._parse_hashed_requirements(inventory, text, rel)
                else:
                    continue
            except (OSError, ValueError):
                continue
            if rel not in inventory.stats.manifests_parsed:
                inventory.stats.manifests_parsed.append(rel)

    # -- iteration -------------------------------------------------------------

    def _iter_lockfiles(self) -> list[Path]:
        if self.root.is_file():
            return [self.root]
        out: list[Path] = []
        for path in self.root.rglob("*"):
            if path.is_dir() or any(p in _IGNORE_DIRS for p in path.relative_to(self.root).parts):
                continue
            n = path.name.lower()
            if n in _LOCKFILE_NAMES or (n.startswith("requirements") and n.endswith(".txt")):
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
        *,
        name: str,
        ecosystem: str,
        version: str | None,
        scope: DependencyScope,
        digest: tuple[str, str, str | None] | None = None,
        producer: str | None = None,
        producer_url: str | None = None,
        license_: str | None = None,
    ) -> None:
        """Add one resolved package. ``digest`` is ``(algorithm, hex, artifact)``."""
        ai = _is_ai_package(name, ecosystem)
        ev = Evidence(
            file=rel,
            line_start=max(lineno, 1),
            line_end=max(lineno, 1),
            snippet=snippet.strip()[:200],
            matched_pattern=f"{ecosystem.lower()}-lockfile-entry",
            confidence=0.95,
            detector_id=DETECTOR_ID,
            kind="lockfile",
        )
        inventory.add_entity(
            Package(
                name=name,
                ecosystem=ecosystem,
                version=version,
                # A lockfile entry is a resolved pin by construction.
                version_pinned=bool(version),
                ai=ai,
                dependency_scope=scope,
                license=license_,
                producer=producer,
                producer_url=producer_url,
                content_hash=digest[1] if digest else None,
                hash_algorithm=digest[0] if digest else None,
                hash_artifact=digest[2] if digest else None,
                source_evidence=[ev],
                detector_ids=[DETECTOR_ID],
                usage=UsageState(declared=scope is DependencyScope.DIRECT),
                confidence_factors=ConfidenceFactors(
                    syntax_confidence=1.0,
                    value_resolution_confidence=1.0,
                    framework_identification_confidence=1.0 if ai else 0.9,
                ),
                source_contexts=[classify_source_context(rel)],
            )
        )

    # -- npm -------------------------------------------------------------------

    def _parse_package_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = json.loads(text)
        if not isinstance(data, dict):
            return
        lines = text.splitlines()
        packages = data.get("packages")
        if isinstance(packages, dict):
            self._npm_v3(inventory, packages, lines, rel)
            return
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            self._npm_v1(inventory, deps, lines, rel, direct=True)

    def _npm_v3(
        self, inventory: Inventory, packages: dict[str, Any], lines: list[str], rel: str
    ) -> None:
        """lockfileVersion 2/3: a flat map keyed by install path."""
        index = _line_index(lines, _RE_NPM_PATH)
        root = packages.get("")
        direct: set[str] = set()
        if isinstance(root, dict):
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                entry = root.get(group)
                if isinstance(entry, dict):
                    direct.update(entry)
        for path, entry in packages.items():
            if not path or not isinstance(entry, dict) or entry.get("link") is True:
                continue
            name = str(entry.get("name") or path.split("node_modules/")[-1])
            if not name:
                continue
            lineno = index.get(path, 1)
            self._emit(
                inventory,
                rel,
                lineno,
                lines[lineno - 1] if lineno <= len(lines) else path,
                name=name,
                ecosystem="npm",
                version=_as_str(entry.get("version")),
                scope=(
                    DependencyScope.DIRECT if name in direct else DependencyScope.TRANSITIVE
                ),
                digest=_npm_integrity(entry.get("integrity")),
                producer=_registry_of(_as_str(entry.get("resolved"))),
                producer_url=_as_str(entry.get("resolved")),
                license_=_as_str(entry.get("license")),
            )

    def _npm_v1(
        self,
        inventory: Inventory,
        deps: dict[str, Any],
        lines: list[str],
        rel: str,
        *,
        direct: bool,
    ) -> None:
        """lockfileVersion 1: a recursive ``dependencies`` tree."""
        index = _line_index(lines, _RE_JSON_KEY)
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            lineno = index.get(name, 1)
            self._emit(
                inventory,
                rel,
                lineno,
                lines[lineno - 1] if lineno <= len(lines) else name,
                name=name,
                ecosystem="npm",
                version=_as_str(entry.get("version")),
                scope=DependencyScope.DIRECT if direct else DependencyScope.TRANSITIVE,
                digest=_npm_integrity(entry.get("integrity")),
                producer=_registry_of(_as_str(entry.get("resolved"))),
                producer_url=_as_str(entry.get("resolved")),
            )
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                self._npm_v1(inventory, nested, lines, rel, direct=False)

    # -- PyPI ------------------------------------------------------------------

    def _parse_pipfile_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = json.loads(text)
        if not isinstance(data, dict):
            return
        lines = text.splitlines()
        index = _line_index(lines, _RE_JSON_KEY)
        for group in ("default", "develop"):
            section = data.get(group)
            if not isinstance(section, dict):
                continue
            for name, entry in section.items():
                if not isinstance(entry, dict):
                    continue
                lineno = index.get(name, 1)
                self._emit(
                    inventory,
                    rel,
                    lineno,
                    lines[lineno - 1] if lineno <= len(lines) else name,
                    name=name,
                    ecosystem="PyPI",
                    version=_strip_pin(_as_str(entry.get("version"))),
                    # Pipfile.lock flattens the graph; Pipfile holds the direct set.
                    scope=DependencyScope.TRANSITIVE,
                    digest=_first_prefixed_hash(entry.get("hashes")),
                    producer="pypi.org",
                    producer_url="https://pypi.org/simple",
                )

    def _parse_poetry_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = _load_toml(text)
        if data is None:
            return
        index = _line_index(text.splitlines(), _RE_TOML_NAME)
        for entry in _as_dicts(data.get("package")):
            name = _as_str(entry.get("name"))
            if not name:
                continue
            files = entry.get("files")
            self._emit(
                inventory,
                rel,
                index.get(name, 1),
                f'name = "{name}"',
                name=name,
                ecosystem="PyPI",
                version=_as_str(entry.get("version")),
                scope=DependencyScope.TRANSITIVE,
                digest=_poetry_digest(files),
                producer="pypi.org",
                producer_url="https://pypi.org/simple",
            )

    def _parse_uv_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = _load_toml(text)
        if data is None:
            return
        index = _line_index(text.splitlines(), _RE_TOML_NAME)
        for entry in _as_dicts(data.get("package")):
            name = _as_str(entry.get("name"))
            if not name:
                continue
            self._emit(
                inventory,
                rel,
                index.get(name, 1),
                f'name = "{name}"',
                name=name,
                ecosystem="PyPI",
                version=_as_str(entry.get("version")),
                scope=DependencyScope.TRANSITIVE,
                digest=_uv_digest(entry),
                producer="pypi.org",
                producer_url="https://pypi.org/simple",
            )

    def _parse_hashed_requirements(self, inventory: Inventory, text: str, rel: str) -> None:
        """``pip-compile --generate-hashes`` output: exact pins plus digests.

        Only hash-pinned entries are emitted here; plain requirements are the
        DependencyCollector's job.
        """
        for lineno, logical in _logical_lines(text):
            if "--hash=" not in logical:
                continue
            pin = _RE_REQ_PIN.match(logical.strip())
            if not pin:
                continue
            hashes = _RE_REQ_HASH.findall(logical)
            digest = None
            if hashes:
                alg, value = sorted(hashes)[0]
                digest = _normalize_digest(alg, value)
            self._emit(
                inventory,
                rel,
                lineno,
                logical.split("--hash=")[0],
                name=pin.group(1),
                ecosystem="PyPI",
                version=pin.group(2),
                scope=DependencyScope.DIRECT,
                digest=digest,
                producer="pypi.org",
                producer_url="https://pypi.org/simple",
            )

    # -- other ecosystems ------------------------------------------------------

    def _parse_cargo_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = _load_toml(text)
        if data is None:
            return
        index = _line_index(text.splitlines(), _RE_TOML_NAME)
        for entry in _as_dicts(data.get("package")):
            name = _as_str(entry.get("name"))
            if not name:
                continue
            checksum = _as_str(entry.get("checksum"))
            self._emit(
                inventory,
                rel,
                index.get(name, 1),
                f'name = "{name}"',
                name=name,
                ecosystem="crates.io",
                version=_as_str(entry.get("version")),
                scope=DependencyScope.TRANSITIVE,
                digest=_normalize_digest(None, checksum) if checksum else None,
                # A vendored crate has no checksum and no registry.
                producer="crates.io" if checksum else None,
                producer_url="https://crates.io" if checksum else None,
            )

    def _parse_composer_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = json.loads(text)
        if not isinstance(data, dict):
            return
        index = _line_index(text.splitlines(), _RE_JSON_NAME)
        for group, scope in (
            ("packages", DependencyScope.DIRECT),
            ("packages-dev", DependencyScope.TRANSITIVE),
        ):
            for entry in _as_dicts(data.get(group)):
                name = _as_str(entry.get("name"))
                if not name:
                    continue
                dist = entry.get("dist") if isinstance(entry.get("dist"), dict) else {}
                shasum = _as_str(dist.get("shasum")) if dist else None
                licenses = entry.get("license")
                self._emit(
                    inventory,
                    rel,
                    index.get(name, 1),
                    f'"name": "{name}"',
                    name=name,
                    ecosystem="Packagist",
                    version=_as_str(entry.get("version")),
                    scope=scope,
                    digest=_normalize_digest(None, shasum) if shasum else None,
                    producer=_registry_of(_as_str(dist.get("url")) if dist else None),
                    producer_url=_as_str(dist.get("url")) if dist else None,
                    license_=(
                        licenses[0]
                        if isinstance(licenses, list) and licenses and isinstance(licenses[0], str)
                        else None
                    ),
                )

    def _parse_gemfile_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        """Gemfile.lock records the resolved graph but no digests."""
        lines = text.splitlines()
        direct: set[str] = set()
        in_dependencies = False
        for line in lines:
            if line.strip() == "DEPENDENCIES":
                in_dependencies = True
                continue
            if in_dependencies:
                if not line.strip():
                    in_dependencies = False
                    continue
                match = _RE_GEM_DIRECT.match(line)
                if match:
                    direct.add(match.group(1))

        remote: str | None = None
        in_specs = False
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("remote:"):
                remote = stripped.split("remote:", 1)[1].strip() or None
            if stripped == "specs:":
                in_specs = True
                continue
            if in_specs and stripped and not line.startswith("  "):
                in_specs = False
            if not in_specs:
                continue
            match = _RE_GEM_SPEC.match(line)
            if not match:
                continue
            name = match.group(1)
            self._emit(
                inventory,
                rel,
                lineno,
                line,
                name=name,
                ecosystem="RubyGems",
                version=match.group(2),
                scope=(
                    DependencyScope.DIRECT if name in direct else DependencyScope.TRANSITIVE
                ),
                producer=_registry_of(remote) or ("rubygems.org" if remote else None),
                producer_url=remote,
            )


# ── helpers ──────────────────────────────────────────────────────────────────


def _line_index(lines: list[str], pattern: re.Pattern[str]) -> dict[str, int]:
    """Map the first line number each captured key appears on (1-indexed).

    One pass over the file keeps evidence line numbers cheap even on a lockfile
    with thousands of entries.
    """
    index: dict[str, int] = {}
    for lineno, line in enumerate(lines, 1):
        match = pattern.match(line)
        if match:
            key = match.group(1)
            index.setdefault(key, lineno)
            # npm keys are install paths; also index the bare package name.
            if "node_modules/" in key:
                index.setdefault(key.split("node_modules/")[-1], lineno)
    return index


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations, keeping the line number of the first line."""
    out: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 1
    for lineno, line in enumerate(text.splitlines(), 1):
        if not buffer:
            start = lineno
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue
        buffer.append(stripped)
        out.append((start, " ".join(part.strip() for part in buffer)))
        buffer = []
    if buffer:
        out.append((start, " ".join(part.strip() for part in buffer)))
    return out


def _normalize_digest(
    algorithm: str | None, value: str | None, artifact: str | None = None
) -> tuple[str, str, str | None] | None:
    """Return ``(CycloneDX algorithm, lowercase hex, artifact)`` or ``None``.

    CycloneDX only accepts hex digests of a known length, so anything that does
    not look like one is dropped rather than emitted as an unverifiable string.
    """
    if not value:
        return None
    digest = value.strip().lower()
    if ":" in digest:
        prefix, _, rest = digest.partition(":")
        algorithm = algorithm or prefix
        digest = rest
    if not re.fullmatch(r"[a-f0-9]+", digest):
        return None
    by_length = _ALG_BY_LENGTH.get(len(digest))
    if by_length is None:
        return None
    # The declared algorithm only wins when the digest length agrees with it —
    # a mislabeled digest is worse than an inferred one.
    named = _ALG_NAMES.get((algorithm or "").strip().lower())
    return (named if named == by_length else by_length), digest, artifact


def _npm_integrity(value: Any) -> tuple[str, str, str | None] | None:
    """``sha512-<base64>`` (Subresource Integrity) -> a hex digest."""
    if not isinstance(value, str) or "-" not in value:
        return None
    algorithm, _, encoded = value.partition("-")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _normalize_digest(algorithm, raw.hex())


def _first_prefixed_hash(value: Any) -> tuple[str, str, str | None] | None:
    """Pick one digest from a ``["sha256:…", …]`` list, deterministically."""
    if not isinstance(value, list):
        return None
    candidates = sorted(v for v in value if isinstance(v, str))
    for candidate in candidates:
        digest = _normalize_digest(None, candidate)
        if digest:
            return digest
    return None


def _poetry_digest(files: Any) -> tuple[str, str, str | None] | None:
    """poetry.lock lists one digest per artifact; prefer the sdist."""
    if not isinstance(files, list):
        return None
    entries = [f for f in files if isinstance(f, dict) and isinstance(f.get("hash"), str)]
    if not entries:
        return None
    entries.sort(key=lambda f: (not str(f.get("file", "")).endswith(".tar.gz"), str(f.get("file"))))
    chosen = entries[0]
    return _normalize_digest(None, str(chosen["hash"]), _as_str(chosen.get("file")))


def _uv_digest(entry: dict[str, Any]) -> tuple[str, str, str | None] | None:
    """uv.lock records an ``sdist`` table and a ``wheels`` array."""
    sdist = entry.get("sdist")
    if isinstance(sdist, dict) and isinstance(sdist.get("hash"), str):
        return _normalize_digest(
            None, sdist["hash"], _artifact_name(_as_str(sdist.get("url")))
        )
    wheels = entry.get("wheels")
    if isinstance(wheels, list):
        for wheel in wheels:
            if isinstance(wheel, dict) and isinstance(wheel.get("hash"), str):
                return _normalize_digest(
                    None, wheel["hash"], _artifact_name(_as_str(wheel.get("url")))
                )
    return None


def _registry_of(url: str | None) -> str | None:
    """Host of a resolved artifact URL — the entity that supplied the artifact."""
    if not url or "://" not in url:
        return None
    host = url.split("://", 1)[1].split("/", 1)[0]
    return host or None


def _artifact_name(url: str | None) -> str | None:
    return url.rstrip("/").rsplit("/", 1)[-1] if url else None


def _strip_pin(version: str | None) -> str | None:
    return version[2:] if version and version.startswith("==") else version


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
