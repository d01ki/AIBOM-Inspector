"""LockfileCollector — resolved dependencies, artifact digests, and registries.

A manifest states what a project *asks for*; a lockfile states what it actually
gets. That difference is exactly what the 2026 CISA SBOM minimum elements ask
for and what a manifest cannot supply:

* **Coverage** — transitive dependencies, not just the top level;
* **Component Version** — the resolved pin, not a range;
* **Component Hash** + **Component Hash Algorithm** — the artifact digest the
  package manager verified on install;
* **Component Producer** — the registry that supplied the artifact.

Supported lockfiles: ``package-lock.json``, ``pnpm-lock.yaml`` (v5, v6, v9)
and ``yarn.lock`` (classic and berry) for npm; ``Pipfile.lock``,
``poetry.lock``, ``uv.lock`` and hash-pinned ``requirements*.txt`` (PyPI);
``Cargo.lock`` (crates.io), ``composer.lock`` (Packagist) and ``Gemfile.lock``
(RubyGems). Everything is parsed as text — nothing is installed or executed;
the YAML ones go through :mod:`aibom.collectors.blockyaml`.

Each lockfile that records the resolved graph (all but ``Pipfile.lock`` and
hash-pinned requirements) also yields ``depends_on`` edges between the packages
*it* resolved, each pinned to the line that declares the dependency. A
requirement on something the lockfile does not resolve (a platform package such
as ``php``, an extra that was not installed) is not an edge: no evidence, no
claim.

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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aibom.collectors import blockyaml
from aibom.collectors.base import Collector
from aibom.collectors.dependencies import _IGNORE_DIRS, _is_ai_package, _load_toml
from aibom.detectors.python.parser import classify_source_context
from aibom.inventory import Inventory
from aibom.models.analysis import ConfidenceFactors, UsageState
from aibom.models.entities import DependencyScope, Package, Relationship, RelationshipType
from aibom.models.evidence import Evidence

DETECTOR_ID = "lockfile.dependencies"

# Lockfiles we recognise but do not parse (docs/limitations.md). They are
# recorded, so the coverage notes can say "present but not parsed" instead of
# the false "no lockfile".
_UNPARSED_LOCKFILE_NAMES = {"bun.lock", "bun.lockb"}

# Dependency groups a pnpm importer or package entry lists. peerDependencies
# are ranges, not resolutions; a resolved peer appears in these groups.
_PNPM_DEP_GROUPS = ("dependencies", "devDependencies", "optionalDependencies")
_YARN_DEP_GROUPS = ("dependencies", "optionalDependencies")

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
_RE_GEM_DEP = re.compile(r"^ {6}([A-Za-z0-9_.\-]+)")
_RE_PYPI_SEP = re.compile(r"[-_.]+")

# Where one lockfile entry ends: the next entry's header line.
_RE_TOML_ENTRY = re.compile(r"^\[\[package\]\]")
_RE_NPM_ENTRY = re.compile(r'^\s*"(?:[^"]*/)?node_modules/[^"]+"\s*:\s*\{')
_RE_REQ_PIN = re.compile(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")


class LockfileCollector(Collector):
    """Inventory every resolved dependency, with its digest and registry."""

    name = "lockfiles"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        # Per-lockfile state: the packages it resolved, and the dependency
        # declarations seen so far as (ecosystem, parent, child, line).
        self._resolved: dict[tuple[str, str], Package] = {}
        self._declared: list[tuple[str, str, str, int]] = []

    def collect(self, inventory: Inventory) -> None:
        if DETECTOR_ID not in inventory.stats.detectors_run:
            inventory.stats.detectors_run.append(DETECTOR_ID)
        for path in self._iter_lockfiles():
            rel = self._rel(path)
            name = path.name.lower()
            if name in _UNPARSED_LOCKFILE_NAMES:
                if rel not in inventory.stats.lockfiles_unparsed:
                    inventory.stats.lockfiles_unparsed.append(rel)
                continue
            parse = _parser_for(name)
            if parse is None:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                self._resolved, self._declared = {}, []
                parse(self, inventory, text, rel)
            except (OSError, ValueError):
                continue
            self._link(inventory, rel, text.splitlines())
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
            if n in _UNPARSED_LOCKFILE_NAMES or _parser_for(n) is not None:
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
        entity = inventory.add_entity(
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
        if isinstance(entity, Package):
            self._resolved[(ecosystem, _key(name, ecosystem))] = entity

    def _declare(
        self,
        ecosystem: str,
        parent: str,
        children: Any,
        lines: list[str],
        start: int,
        entry_header: re.Pattern[str] | None,
    ) -> None:
        """Record ``parent -> child`` for every name in ``children``.

        ``start`` is the parent's header line; each edge's evidence is the
        first line after it that names the child, searched up to the next
        entry header so a later entry's dependency is never borrowed.
        """
        for child in children:
            if not isinstance(child, str) or not child:
                continue
            line = _dep_line(lines, start, child, entry_header)
            self._declared.append((ecosystem, parent, child, line))

    def _link(self, inventory: Inventory, rel: str, lines: list[str]) -> None:
        """Turn this lockfile's declarations into evidence-backed edges."""
        for ecosystem, parent, child, lineno in self._declared:
            src = self._resolved.get((ecosystem, _key(parent, ecosystem)))
            dst = self._resolved.get((ecosystem, _key(child, ecosystem)))
            if src is None or dst is None or src.id == dst.id:
                continue
            snippet = lines[lineno - 1] if 0 < lineno <= len(lines) else child
            inventory.add_relationship(
                Relationship(
                    source_id=src.id,
                    target_id=dst.id,
                    relationship=RelationshipType.DEPENDS_ON,
                    source_evidence=[
                        Evidence(
                            file=rel,
                            line_start=max(lineno, 1),
                            line_end=max(lineno, 1),
                            snippet=snippet.strip()[:200],
                            matched_pattern=f"{ecosystem.lower()}-lockfile-dependency",
                            confidence=0.95,
                            detector_id=DETECTOR_ID,
                            kind="lockfile",
                        )
                    ],
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
            for group in ("dependencies", "optionalDependencies", "peerDependencies"):
                children = entry.get(group)
                if isinstance(children, dict):
                    self._declare("npm", name, children, lines, lineno, _RE_NPM_ENTRY)

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
            requires = entry.get("requires")
            if isinstance(requires, dict):
                self._declare("npm", name, requires, lines, lineno, None)
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                self._npm_v1(inventory, nested, lines, rel, direct=False)

    # -- pnpm ------------------------------------------------------------------

    def _parse_pnpm_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        """pnpm-lock.yaml v5 (``/name/1.0.0``), v6 (``/name@1.0.0``), v9.

        v9 splits each package into ``packages:`` (resolution) and
        ``snapshots:`` (the dependencies it resolved, per peer set); v5 and v6
        keep both in ``packages:``. Direct dependencies are what any importer
        (the root or a workspace package) lists, minus ``link:`` workspaces.
        """
        doc = blockyaml.parse(text)
        major = _pnpm_major(doc.scalar("lockfileVersion"))
        lines = text.splitlines()
        importers = doc.get("importers")
        projects = list(importers.children.values()) if importers else [doc]
        direct: set[str] = set()
        for project in projects:
            for group in _PNPM_DEP_GROUPS:
                deps = project.get(group)
                for dep_name, dep in deps.children.items() if deps else ():
                    resolved = dep.scalar("version") if dep.children else dep.value
                    if resolved and not resolved.startswith("link:"):
                        direct.add(dep_name)
        packages = doc.get("packages")
        if packages is None:
            return
        names: dict[str, str] = {}
        for key, entry in packages.children.items():
            name, version = _pnpm_key(key, major)
            name = entry.scalar("name") or name
            version = entry.scalar("version") or version
            if not name:
                continue
            names[_pnpm_base(key)] = name
            resolution = entry.get("resolution")
            integrity = resolution.scalar("integrity") if resolution else None
            tarball = resolution.scalar("tarball") if resolution else None
            self._emit(
                inventory,
                rel,
                entry.line,
                _line_at(lines, entry.line, key),
                name=name,
                ecosystem="npm",
                version=version,
                scope=DependencyScope.DIRECT if name in direct else DependencyScope.TRANSITIVE,
                digest=_npm_integrity(integrity),
                producer=_registry_of(tarball),
                producer_url=tarball if tarball and "://" in tarball else None,
            )
            self._declare_children("npm", name, entry, _YARN_DEP_GROUPS)
        snapshots = doc.get("snapshots")
        for key, entry in snapshots.children.items() if snapshots else ():
            parent = names.get(_pnpm_base(key)) or _pnpm_key(key, major)[0]
            if parent:
                self._declare_children("npm", parent, entry, _YARN_DEP_GROUPS)

    # -- yarn ------------------------------------------------------------------

    def _parse_yarn_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        """yarn berry (v2+) writes YAML with ``__metadata``; classic does not."""
        if re.search(r"^__metadata:", text, re.MULTILINE):
            self._parse_yarn_berry(inventory, text, rel)
        else:
            self._parse_yarn_classic(inventory, text, rel)

    def _parse_yarn_berry(self, inventory: Inventory, text: str, rel: str) -> None:
        """Entries keyed by descriptors, each with a ``resolution``.

        The ``checksum`` is a digest of yarn's own cache zip, not of the
        registry tarball, so it is not reported as the artifact hash. The
        ``@workspace:`` entries are the scanned project and its workspaces:
        not dependencies, but what they list is the direct set.
        """
        doc = blockyaml.parse(text)
        lines = text.splitlines()
        entries: list[tuple[str, blockyaml.Node]] = []
        direct: set[str] = set()
        for key, entry in doc.children.items():
            if key == "__metadata":
                continue
            resolution = entry.scalar("resolution") or ""
            if "@workspace:" in resolution:
                for group in _PNPM_DEP_GROUPS:
                    deps = entry.get(group)
                    direct.update(deps.children if deps else ())
                continue
            name = _yarn_descriptor_name(resolution)
            if name:
                entries.append((name, entry))
        for name, entry in entries:
            self._emit(
                inventory,
                rel,
                entry.line,
                _line_at(lines, entry.line, name),
                name=name,
                ecosystem="npm",
                version=entry.scalar("version"),
                scope=DependencyScope.DIRECT if name in direct else DependencyScope.TRANSITIVE,
            )
            self._declare_children("npm", name, entry, _YARN_DEP_GROUPS)

    def _parse_yarn_classic(self, inventory: Inventory, text: str, rel: str) -> None:
        """yarn v1: ``"a@^1", a@^2:`` headers, then ``key "value"`` fields.

        The lockfile does not say which entries are direct; the manifest
        (package.json) does, and the merge keeps its DIRECT scope.
        """
        lines = text.splitlines()
        for entry in _yarn_classic_entries(lines):
            fields = entry.fields
            resolved = fields.get("resolved")
            url, _, fragment = (resolved or "").partition("#")
            digest = _npm_integrity(fields.get("integrity"))
            if digest is None and fragment:
                digest = _normalize_digest("sha1", fragment)
            self._emit(
                inventory,
                rel,
                entry.line,
                lines[entry.line - 1],
                name=entry.name,
                ecosystem="npm",
                version=fields.get("version"),
                scope=DependencyScope.TRANSITIVE,
                digest=digest,
                producer=_registry_of(url or None),
                producer_url=url or None,
            )
            for child, lineno in entry.dependencies:
                self._declared.append(("npm", entry.name, child, lineno))

    def _declare_children(
        self, ecosystem: str, parent: str, entry: blockyaml.Node, groups: tuple[str, ...]
    ) -> None:
        """``parent -> child`` for each child in ``groups``, citing the child's own line."""
        for group in groups:
            deps = entry.get(group)
            for child, node in deps.children.items() if deps else ():
                if child and not (node.value or "").startswith("link:"):
                    self._declared.append((ecosystem, parent, child, node.line))

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
        lines = text.splitlines()
        index = _line_index(lines, _RE_TOML_NAME)
        for entry in _as_dicts(data.get("package")):
            name = _as_str(entry.get("name"))
            if not name:
                continue
            files = entry.get("files")
            lineno = index.get(name, 1)
            self._emit(
                inventory,
                rel,
                lineno,
                f'name = "{name}"',
                name=name,
                ecosystem="PyPI",
                version=_as_str(entry.get("version")),
                scope=DependencyScope.TRANSITIVE,
                digest=_poetry_digest(files),
                producer="pypi.org",
                producer_url="https://pypi.org/simple",
            )
            deps = entry.get("dependencies")
            if isinstance(deps, dict):
                self._declare("PyPI", name, deps, lines, lineno, _RE_TOML_ENTRY)

    def _parse_uv_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = _load_toml(text)
        if data is None:
            return
        lines = text.splitlines()
        index = _line_index(lines, _RE_TOML_NAME)
        for entry in _as_dicts(data.get("package")):
            name = _as_str(entry.get("name"))
            if not name or _is_uv_project(entry):
                continue
            lineno = index.get(name, 1)
            self._emit(
                inventory,
                rel,
                lineno,
                f'name = "{name}"',
                name=name,
                ecosystem="PyPI",
                version=_as_str(entry.get("version")),
                scope=DependencyScope.TRANSITIVE,
                digest=_uv_digest(entry),
                producer="pypi.org",
                producer_url="https://pypi.org/simple",
            )
            children = [_as_str(d.get("name")) for d in _as_dicts(entry.get("dependencies"))]
            for group in ("optional-dependencies", "dev-dependencies"):
                extra = entry.get(group)
                if isinstance(extra, dict):
                    for deps in extra.values():
                        children += [_as_str(d.get("name")) for d in _as_dicts(deps)]
            self._declare("PyPI", name, children, lines, lineno, _RE_TOML_ENTRY)

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
        lines = text.splitlines()
        index = _line_index(lines, _RE_TOML_NAME)
        for entry in _as_dicts(data.get("package")):
            name = _as_str(entry.get("name"))
            if not name:
                continue
            checksum = _as_str(entry.get("checksum"))
            lineno = index.get(name, 1)
            self._emit(
                inventory,
                rel,
                lineno,
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
            deps = entry.get("dependencies")
            if isinstance(deps, list):
                # "serde" or "serde 1.0.1 (registry+...)" when versions coexist.
                children = [d.split()[0] for d in deps if isinstance(d, str) and d.strip()]
                self._declare("crates.io", name, children, lines, lineno, _RE_TOML_ENTRY)

    def _parse_composer_lock(self, inventory: Inventory, text: str, rel: str) -> None:
        data = json.loads(text)
        if not isinstance(data, dict):
            return
        lines = text.splitlines()
        index = _line_index(lines, _RE_JSON_NAME)
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
                lineno = index.get(name, 1)
                self._emit(
                    inventory,
                    rel,
                    lineno,
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
                require = entry.get("require")
                if isinstance(require, dict):
                    # Platform requirements (php, ext-*) are never locked, so
                    # they resolve to nothing and are dropped in _link.
                    self._declare("Packagist", name, require, lines, lineno, _RE_JSON_NAME)

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
        parent: str | None = None
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
            dep = _RE_GEM_DEP.match(line)
            if dep:
                if parent is not None:
                    self._declared.append(("RubyGems", parent, dep.group(1), lineno))
                continue
            match = _RE_GEM_SPEC.match(line)
            if not match:
                continue
            name = match.group(1)
            parent = name
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


_Parser = Callable[[LockfileCollector, Inventory, str, str], None]

# Lockfile name (lowercased) -> its parser.
_PARSERS: dict[str, _Parser] = {
    "package-lock.json": LockfileCollector._parse_package_lock,
    "pnpm-lock.yaml": LockfileCollector._parse_pnpm_lock,
    "yarn.lock": LockfileCollector._parse_yarn_lock,
    "pipfile.lock": LockfileCollector._parse_pipfile_lock,
    "poetry.lock": LockfileCollector._parse_poetry_lock,
    "uv.lock": LockfileCollector._parse_uv_lock,
    "cargo.lock": LockfileCollector._parse_cargo_lock,
    "composer.lock": LockfileCollector._parse_composer_lock,
    "gemfile.lock": LockfileCollector._parse_gemfile_lock,
}


def _parser_for(name: str) -> _Parser | None:
    """The parser for a lowercased file name, or ``None`` if it is not a lockfile."""
    if name.startswith("requirements") and name.endswith(".txt"):
        return LockfileCollector._parse_hashed_requirements
    return _PARSERS.get(name)


# ── helpers ──────────────────────────────────────────────────────────────────


class _YarnEntry:
    """One yarn v1 entry: its header line, name, fields and dependency lines."""

    __slots__ = ("line", "name", "fields", "dependencies")

    def __init__(self, line: int, name: str) -> None:
        self.line = line
        self.name = name
        self.fields: dict[str, str] = {}
        self.dependencies: list[tuple[str, int]] = []


def _yarn_classic_entries(lines: list[str]) -> list[_YarnEntry]:
    """Split a yarn v1 lockfile into entries; lines outside the format are skipped."""
    entries: list[_YarnEntry] = []
    current: _YarnEntry | None = None
    section: str | None = None
    for lineno, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            current, section = None, None
            if stripped.endswith(":"):
                descriptors = blockyaml.split_top_level(stripped[:-1])
                name = _yarn_descriptor_name(blockyaml.unquote(descriptors[0]))
                if name:
                    current = _YarnEntry(lineno, name)
                    entries.append(current)
        elif current is None:
            continue
        elif indent == 2:
            section = None
            if stripped.endswith(":"):
                section = stripped[:-1]
            else:
                key, _, value = stripped.partition(" ")
                if value:
                    current.fields.setdefault(key, blockyaml.unquote(value))
        elif section in _YARN_DEP_GROUPS:
            if stripped[0] == '"':
                end = stripped.find('"', 1)
                child = stripped[1:end] if end > 0 else ""
            else:
                child = stripped.split(" ", 1)[0]
            if child:
                current.dependencies.append((child, lineno))
    return [e for e in entries if e.fields.get("version")]


def _yarn_descriptor_name(descriptor: str) -> str | None:
    """``@scope/pkg@npm:^1`` -> ``@scope/pkg``; an alias keeps its own name."""
    at = descriptor.find("@", 1)
    return descriptor[:at] if at > 0 else None


def _pnpm_major(version: str | None) -> int:
    """``'9.0'`` -> 9; an unreadable version is treated as the current format."""
    try:
        return int(float(version or ""))
    except ValueError:
        return 9


def _pnpm_base(key: str) -> str:
    """A package key without its leading ``/`` and ``(peer@1)`` suffix."""
    return key[1:].split("(", 1)[0] if key.startswith("/") else key.split("(", 1)[0]


def _pnpm_key(key: str, major: int) -> tuple[str | None, str | None]:
    """``/name/1.0.0_peer`` (v5), ``/name@1.0.0(peer)`` (v6), ``name@1.0.0`` (v9)."""
    base = _pnpm_base(key)
    if major < 6:
        name, _, version = base.rpartition("/")
        return (name or None), (version.split("_", 1)[0] or None)
    at = base.rfind("@")
    if at <= 0:
        return None, None
    version = base[at + 1 :]
    # A tarball or git key carries a URL where the version would be.
    return base[:at], (None if ":" in version or "/" in version else version or None)


def _line_at(lines: list[str], lineno: int, fallback: str) -> str:
    return lines[lineno - 1] if 0 < lineno <= len(lines) else fallback



def _key(name: str, ecosystem: str) -> str:
    """Comparison key for a package name within one ecosystem (PEP 503 for PyPI)."""
    lowered = name.strip().lower()
    return _RE_PYPI_SEP.sub("-", lowered) if ecosystem == "PyPI" else lowered


def _dep_line(
    lines: list[str], start: int, child: str, entry_header: re.Pattern[str] | None
) -> int:
    """First line after ``start`` naming ``child``, within the same entry.

    Falls back to ``start`` (the parent's own line) when the child cannot be
    located, so the evidence is never a line from an unrelated entry.
    """
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.\-/]){re.escape(child)}(?![A-Za-z0-9_\-/])", re.IGNORECASE
    )
    for lineno in range(start + 1, len(lines) + 1):
        line = lines[lineno - 1]
        if entry_header is not None and entry_header.match(line):
            break
        if pattern.search(line):
            return lineno
    return start


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


def _is_uv_project(entry: dict[str, Any]) -> bool:
    """The scanned project itself (``virtual``) or its own root (``editable = "."``).

    uv.lock records the project as a ``[[package]]`` whose dependencies are
    the direct ones; it is not a dependency, so it is never emitted.
    """
    source = entry.get("source")
    if not isinstance(source, dict):
        return False
    return "virtual" in source or source.get("editable") == "."


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
