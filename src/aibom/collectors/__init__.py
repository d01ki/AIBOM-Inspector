"""Collectors — pluggable sources of AI supply-chain evidence.

MVP ships the repository (static source) collector. Post-MVP collectors
(Ollama, Docker images, MCP configs, …) implement the same
:class:`~aibom.collectors.base.Collector` interface.
"""

from aibom.collectors.base import Collector
from aibom.collectors.repo import RepoCollector

__all__ = ["Collector", "RepoCollector"]
