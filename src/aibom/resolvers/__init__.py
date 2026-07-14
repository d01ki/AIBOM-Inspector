"""Resolvers — enrich discovered entities with upstream metadata.

A collector finds a *reference* (e.g. the string ``bert-base-uncased`` used in a
``from_pretrained`` call). A resolver turns that reference into a component with
provenance: license, model-card presence, serialization formats, author,
download counts, gated status, and pinned revision. Resolution is always
best-effort and network-optional — a resolver never fails a scan, and never
executes or loads the model it describes.
"""

from __future__ import annotations

from aibom.resolvers.huggingface import HFClient, HuggingFaceResolver

__all__ = ["HFClient", "HuggingFaceResolver"]
