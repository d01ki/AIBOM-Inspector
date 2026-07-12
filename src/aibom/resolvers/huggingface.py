"""Hugging Face resolver — enrich HF model/dataset references with hub metadata.

Given entities discovered by a collector, this queries the public Hugging Face
Hub API (read-only) and fills in license, model-card presence, serialization
formats, author, download counts, gated status, and the resolved commit SHA.

Design constraints:

* **Network-optional.** Any transport error is swallowed; the entity is simply
  left unresolved. A scan must never fail because the hub is unreachable.
* **Cache-backed / offline-friendly.** Responses are cached as JSON on disk, so
  repeated scans and air-gapped runs work against a snapshot (SPEC §3).
* **Static.** It reads metadata only. It never downloads or loads weights.
* **Injectable.** ``HuggingFaceResolver`` takes a client, so tests supply a fake
  and never touch the network.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from aibom.inventory import Inventory
from aibom.models.entities import Dataset, Model

_HF_API = "https://huggingface.co/api"
_USER_AGENT = "aibom-inspector (+https://github.com/d01ki/AIBOM-Inspector)"
_DEFAULT_TIMEOUT = 10.0

# filename extension -> serialization format label
_FORMAT_BY_SUFFIX = {
    ".safetensors": "safetensors", ".gguf": "gguf", ".onnx": "onnx", ".h5": "h5",
    ".pt": "pt", ".pth": "pth", ".ckpt": "ckpt", ".pkl": "pickle", ".pickle": "pickle",
    ".msgpack": "msgpack", ".bin": "bin", ".pb": "pb",
}

# HF repo ids look like "org/name"; anything else is a local path or bare id.
_RE_HF_REPO_ID = re.compile(r"^[A-Za-z0-9][\w\-.]*/[\w\-.]+$")


def _looks_like_hf_repo_id(name: str) -> bool:
    return bool(_RE_HF_REPO_ID.match(name))


class HubClient(Protocol):
    """Minimal read-only hub client contract (so tests can fake it)."""

    def fetch_model(self, repo_id: str) -> dict[str, Any] | None: ...
    def fetch_dataset(self, repo_id: str) -> dict[str, Any] | None: ...


class HFClient:
    """Read-only Hugging Face Hub API client with an on-disk JSON cache.

    Returns ``None`` for any repo that cannot be fetched (404, offline, timeout),
    which the resolver treats as "leave unresolved".
    """

    def __init__(
        self,
        *,
        cache_dir: str | Path | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        offline: bool = False,
    ) -> None:
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir else None
        self.timeout = timeout
        self.offline = offline

    def fetch_model(self, repo_id: str) -> dict[str, Any] | None:
        return self._fetch("models", repo_id)

    def fetch_dataset(self, repo_id: str) -> dict[str, Any] | None:
        return self._fetch("datasets", repo_id)

    # -- internals -------------------------------------------------------------

    def _fetch(self, kind: str, repo_id: str) -> dict[str, Any] | None:
        cached = self._cache_read(kind, repo_id)
        if cached is not None:
            return cached
        if self.offline:
            return None
        url = f"{_HF_API}/{kind}/{repo_id}"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None
        if not isinstance(data, dict):
            return None
        self._cache_write(kind, repo_id, data)
        return data

    def _cache_path(self, kind: str, repo_id: str) -> Path | None:
        if self.cache_dir is None:
            return None
        safe = repo_id.replace("/", "__")
        return self.cache_dir / kind / f"{safe}.json"

    def _cache_read(self, kind: str, repo_id: str) -> dict[str, Any] | None:
        path = self._cache_path(kind, repo_id)
        if path is None or not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None
        return data if isinstance(data, dict) else None

    def _cache_write(self, kind: str, repo_id: str, data: dict[str, Any]) -> None:
        path = self._cache_path(kind, repo_id)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass


class HuggingFaceResolver:
    """Enrich HF-provider ``Model`` and ``Dataset`` entities in an inventory."""

    name = "huggingface"

    def __init__(self, client: HubClient | None = None) -> None:
        self.client = client or HFClient()

    def resolve(self, inventory: Inventory) -> None:
        for entity in inventory.entities:
            if isinstance(entity, Model):
                self._resolve_model(entity)
            elif isinstance(entity, Dataset):
                self._resolve_dataset(entity)

    # -- per-entity ------------------------------------------------------------

    def _resolve_model(self, model: Model) -> None:
        if model.provider != "huggingface" or not _looks_like_hf_repo_id(model.name):
            return
        meta = self.client.fetch_model(model.name)
        if meta is None:
            return
        model.author = model.author or meta.get("author") or model.name.split("/", 1)[0]
        model.license = model.license or _license_from(meta)
        model.downloads = _as_int(meta.get("downloads"))
        model.gated = _as_gated(meta.get("gated"))
        model.last_modified = _as_str(meta.get("lastModified"))
        siblings = _sibling_names(meta)
        model.has_model_card = _has_model_card(meta, siblings)
        for fmt in _formats_from(siblings):
            if fmt not in model.formats:
                model.formats.append(fmt)
        # If the reference pinned a revision, record the resolved commit SHA.
        if model.revision_pinned and not model.revision and meta.get("sha"):
            model.revision = _as_str(meta.get("sha"))
        model.resolved = True

    def _resolve_dataset(self, dataset: Dataset) -> None:
        if dataset.source != "huggingface" or not _looks_like_hf_repo_id(dataset.name):
            return
        meta = self.client.fetch_dataset(dataset.name)
        if meta is None:
            return
        dataset.author = dataset.author or meta.get("author") or dataset.name.split("/", 1)[0]
        dataset.license = dataset.license or _license_from(meta)
        dataset.downloads = _as_int(meta.get("downloads"))
        dataset.gated = _as_gated(meta.get("gated"))
        dataset.last_modified = _as_str(meta.get("lastModified"))
        if dataset.provenance is None and meta.get("author"):
            dataset.provenance = f"huggingface author: {meta.get('author')}"
        dataset.resolved = True


# ── helpers ──────────────────────────────────────────────────────────────────


def _sibling_names(meta: dict[str, Any]) -> list[str]:
    siblings = meta.get("siblings")
    if not isinstance(siblings, list):
        return []
    names: list[str] = []
    for s in siblings:
        if isinstance(s, dict) and isinstance(s.get("rfilename"), str):
            names.append(s["rfilename"])
    return names


def _formats_from(filenames: list[str]) -> list[str]:
    out: list[str] = []
    for name in filenames:
        suffix = Path(name).suffix.lower()
        fmt = _FORMAT_BY_SUFFIX.get(suffix)
        if fmt and fmt not in out:
            out.append(fmt)
    return out


def _has_model_card(meta: dict[str, Any], siblings: list[str]) -> bool:
    card = meta.get("cardData")
    if isinstance(card, dict) and card:
        return True
    return any(name.lower() == "readme.md" for name in siblings)


def _license_from(meta: dict[str, Any]) -> str | None:
    card = meta.get("cardData")
    if isinstance(card, dict):
        lic = card.get("license")
        if isinstance(lic, str) and lic:
            return lic
        if isinstance(lic, list) and lic and isinstance(lic[0], str):
            return lic[0]
    # fall back to a ``license:xxx`` tag
    tags = meta.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("license:"):
                return tag.split(":", 1)[1] or None
    return None


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_gated(value: Any) -> bool | None:
    # HF reports gated as False or a string ("auto"/"manual").
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() not in {"", "false"}
    return None
