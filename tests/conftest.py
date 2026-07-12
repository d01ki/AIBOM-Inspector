from __future__ import annotations

from pathlib import Path

import pytest

from aibom import __version__
from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory, ScanMetadata

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-ai-app"


@pytest.fixture
def fixture_inventory() -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(FIXTURE)))
    RepoCollector(FIXTURE).collect(inv)
    return inv
