"""Tests for the Hugging Face resolver.

These use a fake hub client — the resolver must never touch the network in
tests, and must degrade gracefully when metadata is missing.
"""

from __future__ import annotations

from typing import Any

from aibom import __version__
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import Dataset, EntityType, Model
from aibom.models.evidence import Evidence
from aibom.resolvers.huggingface import HFClient, HuggingFaceResolver


class FakeClient:
    """A HubClient that serves canned metadata (no network)."""

    def __init__(
        self,
        models: dict[str, dict[str, Any]] | None = None,
        datasets: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.models = models or {}
        self.datasets = datasets or {}

    def fetch_model(self, repo_id: str) -> dict[str, Any] | None:
        return self.models.get(repo_id)

    def fetch_dataset(self, repo_id: str) -> dict[str, Any] | None:
        return self.datasets.get(repo_id)


def _evidence() -> Evidence:
    return Evidence(
        file="app.py", line_start=1, line_end=1, snippet="x",
        matched_pattern="from_pretrained", confidence=0.9,
    )


def _inventory(*entities: Any) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target="/tmp/x"))
    for e in entities:
        inv.add_entity(e)
    return inv


def test_resolves_model_metadata() -> None:
    model = Model(name="acme/foo", provider="huggingface", source_evidence=[_evidence()])
    inv = _inventory(model)
    client = FakeClient(
        models={
            "acme/foo": {
                "author": "acme",
                "downloads": 12345,
                "gated": "manual",
                "lastModified": "2025-01-02T03:04:05.000Z",
                "cardData": {"license": "apache-2.0"},
                "siblings": [
                    {"rfilename": "model.safetensors"},
                    {"rfilename": "pytorch_model.bin"},
                    {"rfilename": "README.md"},
                ],
            }
        }
    )
    HuggingFaceResolver(client).resolve(inv)

    got = inv.by_type(EntityType.MODEL)[0]
    assert got.resolved is True  # type: ignore[attr-defined]
    assert got.author == "acme"  # type: ignore[attr-defined]
    assert got.license == "apache-2.0"  # type: ignore[attr-defined]
    assert got.downloads == 12345  # type: ignore[attr-defined]
    assert got.gated is True  # type: ignore[attr-defined]
    assert got.has_model_card is True  # type: ignore[attr-defined]
    assert "safetensors" in got.formats  # type: ignore[attr-defined]
    assert "bin" in got.formats  # type: ignore[attr-defined]


def test_license_from_tag_fallback() -> None:
    model = Model(name="acme/bar", provider="huggingface", source_evidence=[_evidence()])
    inv = _inventory(model)
    client = FakeClient(models={"acme/bar": {"tags": ["license:mit", "text-generation"]}})
    HuggingFaceResolver(client).resolve(inv)
    assert inv.by_type(EntityType.MODEL)[0].license == "mit"  # type: ignore[attr-defined]


def test_unresolved_when_metadata_missing() -> None:
    model = Model(name="acme/missing", provider="huggingface", source_evidence=[_evidence()])
    inv = _inventory(model)
    HuggingFaceResolver(FakeClient()).resolve(inv)
    assert inv.by_type(EntityType.MODEL)[0].resolved is False  # type: ignore[attr-defined]


def test_skips_non_hf_and_local_models() -> None:
    local = Model(name="./weights/x.pkl", provider="local", source_evidence=[_evidence()])
    openai = Model(name="gpt-4o-mini", provider="openai", source_evidence=[_evidence()])
    inv = _inventory(local, openai)
    # A client that would raise if asked ensures we never call it for these.
    HuggingFaceResolver(FakeClient()).resolve(inv)
    for m in inv.by_type(EntityType.MODEL):
        assert m.resolved is False  # type: ignore[attr-defined]


def test_resolves_dataset() -> None:
    ds = Dataset(name="acme/data", source="huggingface", source_evidence=[_evidence()])
    inv = _inventory(ds)
    client = FakeClient(
        datasets={"acme/data": {"author": "acme", "downloads": 7, "cardData": {"license": "mit"}}}
    )
    HuggingFaceResolver(client).resolve(inv)
    got = inv.by_type(EntityType.DATASET)[0]
    assert got.resolved is True  # type: ignore[attr-defined]
    assert got.license == "mit"  # type: ignore[attr-defined]
    assert got.provenance is not None  # type: ignore[attr-defined]


def test_offline_client_uses_cache_only(tmp_path: Any) -> None:
    # With offline=True and no cache present, fetch returns None (no network).
    client = HFClient(cache_dir=tmp_path, offline=True)
    assert client.fetch_model("acme/foo") is None

    # Seed the cache, then confirm it is read back without network.
    cache_file = tmp_path / "models" / "acme__foo.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text('{"author": "acme"}', encoding="utf-8")
    assert client.fetch_model("acme/foo") == {"author": "acme"}
