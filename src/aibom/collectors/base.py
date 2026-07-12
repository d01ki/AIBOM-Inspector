"""The Collector plugin interface.

A Collector inspects some source (a repository, a Docker image, an Ollama host…)
and *adds* entities and relationships to a shared :class:`Inventory`. Collectors
must be static and side-effect free with respect to the target: they never
execute scanned code or load scanned models.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aibom.inventory import Inventory


class Collector(ABC):
    """Base class every collector implements."""

    #: Stable, short identifier used in entry points and CLI selection.
    name: str = "collector"

    @abstractmethod
    def collect(self, inventory: Inventory) -> None:
        """Discover entities/relationships and add them to ``inventory``.

        Implementations must be idempotent: running twice against the same
        target yields the same inventory (the Inventory deduplicates by key).
        """
        raise NotImplementedError
