"""pnpm-lock.yaml and yarn.lock: the JS lockfiles that are not package-lock.json.

Both are read as text by a small block-YAML reader (no YAML dependency), so
these tests pin the shapes each generation of the format actually writes:
pnpm v5 / v6 / v9 and yarn classic (v1) / berry (v2+). Each asserts what must
*not* be claimed as well: workspace links, the scanned project itself, peer
ranges that were never resolved, and yarn berry's cache checksum, which is a
digest of yarn's own zip rather than of the registry artifact.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.collectors.dependencies import DependencyCollector
from aibom.collectors.lockfiles import LockfileCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import DependencyScope, EntityType, Package, RelationshipType

FIXTURES = Path(__file__).parent / "fixtures" / "locked-js-app"
# A well-formed (fake) Subresource Integrity value: base64 of 64 bytes.
SRI = "sha512-" + "A" * 86 + "=="


def _scan(root: Path, *, manifests: bool = False) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version="test", target=str(root)))
    if manifests:
        DependencyCollector(root).collect(inv)
    LockfileCollector(root).collect(inv)
    return inv


def _packages(inv: Inventory) -> dict[str, Package]:
    return {e.name: e for e in inv.by_type(EntityType.PACKAGE) if isinstance(e, Package)}


def _edges(inv: Inventory) -> set[tuple[str, str]]:
    names = {e.id: e.name for e in inv.entities}
    return {
        (names[r.source_id], names[r.target_id])
        for r in inv.relationships
        if r.relationship is RelationshipType.DEPENDS_ON
    }


def _line(path: Path, lineno: int) -> str:
    return path.read_text(encoding="utf-8").splitlines()[lineno - 1]


# -- pnpm v9 ------------------------------------------------------------------


@pytest.fixture(scope="module")
def pnpm9() -> Inventory:
    return _scan(FIXTURES / "pnpm-v9")


def test_pnpm9_resolves_every_package_with_its_pin(pnpm9: Inventory) -> None:
    pkgs = _packages(pnpm9)
    assert set(pkgs) == {
        "@anthropic-ai/sdk",
        "ai",
        "js-tokens",
        "loose-envify",
        "private-lib",
        "react",
        "typescript",
        "zod",
    }
    # The peer suffix "(react@18.3.1)(zod@3.23.8)" is not part of the version.
    assert pkgs["ai"].version == "4.0.2"
    assert all(p.ecosystem == "npm" and p.version_pinned for p in pkgs.values())
    assert pkgs["@anthropic-ai/sdk"].ai and pkgs["ai"].ai
    assert not pkgs["react"].ai


def test_pnpm9_scope_comes_from_every_importer(pnpm9: Inventory) -> None:
    pkgs = _packages(pnpm9)
    for direct in ("@anthropic-ai/sdk", "ai", "react", "typescript", "private-lib"):
        assert pkgs[direct].dependency_scope is DependencyScope.DIRECT, direct
    # zod is a direct dependency of the packages/shared workspace.
    assert pkgs["zod"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["loose-envify"].dependency_scope is DependencyScope.TRANSITIVE
    assert pkgs["js-tokens"].dependency_scope is DependencyScope.TRANSITIVE


def test_pnpm9_a_workspace_link_is_not_a_package(pnpm9: Inventory) -> None:
    assert "shared" not in _packages(pnpm9)
    assert not any(e.name == "packages/shared" for e in pnpm9.entities)


def test_pnpm9_integrity_and_tarball(pnpm9: Inventory) -> None:
    pkgs = _packages(pnpm9)
    react = pkgs["react"]
    assert react.hash_algorithm == "SHA-512"
    assert react.content_hash is not None and len(react.content_hash) == 128
    # pnpm records no registry for default-registry packages: no claim.
    assert react.producer is None
    private = pkgs["private-lib"]
    assert private.version == "1.0.0"
    assert private.content_hash is None
    assert private.producer == "npm.example.com"
    assert private.producer_url == "https://npm.example.com/private-lib/-/private-lib-1.0.0.tgz"


def test_pnpm9_edges_come_from_snapshots_and_cite_the_line(pnpm9: Inventory) -> None:
    edges = _edges(pnpm9)
    assert {
        ("ai", "zod"),
        ("ai", "react"),
        ("react", "loose-envify"),
        ("loose-envify", "js-tokens"),
    } <= edges
    # A peer range in `packages:` is not a resolved dependency: the snapshot
    # of @anthropic-ai/sdk is `{}`, so it depends on nothing.
    assert not any(src == "@anthropic-ai/sdk" for src, _ in edges)
    lock = FIXTURES / "pnpm-v9" / "pnpm-lock.yaml"
    names = {e.id: e.name for e in pnpm9.entities}
    for rel in pnpm9.relationships:
        ev = rel.source_evidence[0]
        assert ev.file == "pnpm-lock.yaml"
        assert names[rel.target_id] in _line(lock, ev.line_start)


def test_pnpm9_package_evidence_is_its_packages_entry(pnpm9: Inventory) -> None:
    lock = FIXTURES / "pnpm-v9" / "pnpm-lock.yaml"
    ai = _packages(pnpm9)["ai"]
    ev = ai.source_evidence[0]
    assert ev.kind == "lockfile"
    assert _line(lock, ev.line_start) == "  ai@4.0.2:"


def test_pnpm_lockfile_counts_as_parsed(pnpm9: Inventory) -> None:
    assert pnpm9.stats.lockfiles_unparsed == []
    assert "pnpm-lock.yaml" in pnpm9.stats.manifests_parsed


# -- pnpm v6 and v5 -----------------------------------------------------------


def test_pnpm6_reads_slash_keys_and_inline_dependencies() -> None:
    inv = _scan(FIXTURES / "pnpm-v6")
    pkgs = _packages(inv)
    assert set(pkgs) == {"openai", "node-fetch", "whatwg-url"}
    assert pkgs["openai"].version == "4.52.7"
    assert pkgs["openai"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["node-fetch"].dependency_scope is DependencyScope.TRANSITIVE
    edges = _edges(inv)
    assert edges == {("openai", "node-fetch"), ("node-fetch", "whatwg-url")}
    # `encoding` is an optional peer that was never installed: no node, no edge.
    assert "encoding" not in pkgs


def test_pnpm5_reads_name_slash_version_keys(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: 5.4\n\n"
        "specifiers:\n  '@types/react': ^18.0.0\n  react-dom: ^18.2.0\n\n"
        "dependencies:\n  react-dom: 18.2.0_react@18.2.0\n\n"
        "devDependencies:\n  '@types/react': 18.0.28\n\n"
        "packages:\n\n"
        "  /@types/react/18.0.28:\n"
        f"    resolution: {{integrity: {SRI}}}\n"
        "    dev: true\n\n"
        "  /react-dom/18.2.0_react@18.2.0:\n"
        f"    resolution: {{integrity: {SRI}}}\n"
        "    peerDependencies:\n      react: ^18.2.0\n"
        "    dependencies:\n      react: 18.2.0\n      scheduler: 0.23.0\n"
        "    dev: false\n\n"
        "  /react/18.2.0:\n"
        f"    resolution: {{integrity: {SRI}}}\n"
        "    dev: false\n\n"
        "  /scheduler/0.23.0:\n"
        f"    resolution: {{integrity: {SRI}}}\n"
        "    dev: false\n",
        encoding="utf-8",
    )
    pkgs = _packages(_scan(tmp_path))
    assert set(pkgs) == {"@types/react", "react-dom", "react", "scheduler"}
    # "_react@18.2.0" is v5's peer suffix, not part of the version.
    assert pkgs["react-dom"].version == "18.2.0"
    assert pkgs["@types/react"].version == "18.0.28"
    assert pkgs["react-dom"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["@types/react"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["scheduler"].dependency_scope is DependencyScope.TRANSITIVE
    assert pkgs["scheduler"].hash_algorithm == "SHA-512"


# -- yarn classic (v1) --------------------------------------------------------


@pytest.fixture(scope="module")
def yarn1() -> Inventory:
    return _scan(FIXTURES / "yarn-v1")


def test_yarn1_reads_entries_and_aliases(yarn1: Inventory) -> None:
    pkgs = _packages(yarn1)
    assert set(pkgs) == {
        "@anthropic-ai/sdk",
        "js-tokens",
        "loose-envify",
        "react",
        "string-width-cjs",
    }
    assert pkgs["loose-envify"].version == "1.4.0"
    # An alias installs under its own name; the version is the target's.
    assert pkgs["string-width-cjs"].version == "4.2.3"
    assert pkgs["@anthropic-ai/sdk"].ai
    assert pkgs["react"].producer == "registry.yarnpkg.com"


def test_yarn1_digest_prefers_integrity_then_the_url_sha1(yarn1: Inventory) -> None:
    pkgs = _packages(yarn1)
    assert pkgs["react"].hash_algorithm == "SHA-512"
    # Old yarn wrote no `integrity`; the `#<sha1>` fragment is the tarball digest.
    assert pkgs["js-tokens"].hash_algorithm == "SHA-1"
    assert pkgs["js-tokens"].content_hash is not None
    assert len(pkgs["js-tokens"].content_hash) == 40


def test_yarn1_edges_cite_the_dependency_line(yarn1: Inventory) -> None:
    edges = _edges(yarn1)
    assert edges == {("react", "loose-envify"), ("loose-envify", "js-tokens")}
    # left-pad is an optional dependency yarn did not lock: no node, no edge.
    assert "left-pad" not in _packages(yarn1)
    lock = FIXTURES / "yarn-v1" / "yarn.lock"
    for rel in yarn1.relationships:
        ev = rel.source_evidence[0]
        assert ev.file == "yarn.lock"
        assert _line(lock, ev.line_start).startswith("    ")


def test_yarn1_scope_comes_from_the_manifest() -> None:
    inv = _scan(FIXTURES / "yarn-v1", manifests=True)
    pkgs = _packages(inv)
    assert pkgs["react"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["react"].version == "18.3.1"
    assert pkgs["loose-envify"].dependency_scope is DependencyScope.TRANSITIVE
    assert len([p for p in inv.by_type(EntityType.PACKAGE) if p.name == "react"]) == 1


# -- yarn berry (v2+) ---------------------------------------------------------


@pytest.fixture(scope="module")
def berry() -> Inventory:
    return _scan(FIXTURES / "yarn-berry")


def test_berry_reads_entries_and_skips_the_workspace(berry: Inventory) -> None:
    pkgs = _packages(berry)
    assert set(pkgs) == {"js-tokens", "loose-envify", "openai", "react"}
    assert "yarn-berry-app" not in pkgs
    assert pkgs["openai"].version == "4.52.7"
    assert pkgs["openai"].ai


def test_berry_scope_comes_from_the_workspace_entry(berry: Inventory) -> None:
    pkgs = _packages(berry)
    assert pkgs["openai"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["react"].dependency_scope is DependencyScope.DIRECT
    assert pkgs["loose-envify"].dependency_scope is DependencyScope.TRANSITIVE


def test_berry_cache_checksum_is_not_claimed_as_the_artifact_digest(berry: Inventory) -> None:
    for pkg in _packages(berry).values():
        assert pkg.content_hash is None
        assert pkg.hash_algorithm is None


def test_berry_edges(berry: Inventory) -> None:
    # The workspace -> openai/react declarations are scope, not package edges.
    assert _edges(berry) == {("react", "loose-envify"), ("loose-envify", "js-tokens")}


# -- robustness ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  - [not, a, map\n"),
        ("pnpm-lock.yaml", "\x00\x01 binary garbage {{{{ ::::\n"),
        ("yarn.lock", '"unterminated@^1:\n  version\n'),
        ("yarn.lock", "__metadata:\n  version: 8\n\n\"x@npm:1\":\n  resolution: \n"),
    ],
)
def test_a_malformed_js_lockfile_does_not_fail_the_scan(
    tmp_path: Path, name: str, text: str
) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    inv = _scan(tmp_path)
    assert all(p.name and p.version for p in _packages(inv).values())


def test_bun_lockfiles_are_still_recorded_as_unparsed(tmp_path: Path) -> None:
    (tmp_path / "bun.lockb").write_bytes(b"\x00bun")
    inv = _scan(tmp_path)
    assert inv.stats.lockfiles_unparsed == ["bun.lockb"]
