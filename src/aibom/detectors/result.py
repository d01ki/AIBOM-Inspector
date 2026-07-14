"""Normalized result emitted by a detector before inventory deduplication."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.models.entities import Entity


@dataclass(frozen=True)
class Detection:
    """A detector-produced entity ready to merge into the inventory."""

    entity: Entity
