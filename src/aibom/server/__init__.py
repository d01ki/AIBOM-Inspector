"""HTTP layer — a thin FastAPI wrapper over the scan service.

The API takes a public repository URL, shallow-clones it into a throwaway temp
directory, runs the exact same pipeline the CLI uses, and returns the inventory,
CycloneDX AIBOM, findings, and score as JSON. It never executes the cloned code
(the scanner is static) and cleans up the checkout afterwards.
"""

from __future__ import annotations

__all__ = ["create_app"]


def create_app():  # type: ignore[no-untyped-def]
    """Lazy factory so importing the package never requires FastAPI."""
    from aibom.server.app import create_app as _create_app

    return _create_app()
