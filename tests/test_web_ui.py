"""Guards for the single-page UI, which has no JavaScript test harness.

These are cheap structural checks, not a substitute for opening the page. They
exist because two classes of breakage shipped unnoticed and both are trivially
detectable from the file itself:

1. results were rendered into a container the stylesheet kept at
   ``display: none``, so every analysis succeeded invisibly;
2. removing a feature left ``$("id")`` lookups pointing at markup that no
   longer exists, which throws at load and takes the whole page with it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1] / "web" / "index.html"


@pytest.fixture(scope="module")
def page() -> str:
    return WEB.read_text(encoding="utf-8")


def _results_rule(page: str) -> str:
    """The base ``.results`` declaration block."""
    match = re.search(r"\n  \.results \{(.*?)\}", page, re.S)
    assert match, ".results rule not found; did the stylesheet get restructured?"
    return match.group(1)


def test_results_container_is_not_hidden_by_the_stylesheet(page: str) -> None:
    """`display: none` here outlives `style.display = ""` and hides every result.

    Visibility belongs to the `hidden` attribute, which `[hidden]` implements
    with `!important`, so JavaScript can actually turn it off again.
    """
    assert "display" not in _results_rule(page), (
        "`.results` must not set `display`: the code toggles the `hidden` "
        "attribute, and a stylesheet `display` declaration wins over clearing "
        "an inline style"
    )
    assert "[hidden] { display: none !important; }" in page


def test_results_visibility_is_toggled_by_the_hidden_attribute(page: str) -> None:
    assert 'id="results" tabindex="-1" hidden' in page, "results must start hidden"
    assert '$("results").hidden = false;' in page
    assert '$("results").style.display' not in page, (
        "inline display toggling is what broke the results area; use .hidden"
    )


def test_every_element_id_used_by_the_script_exists_in_the_markup(page: str) -> None:
    """A stale `$("id")` after removing a feature throws and kills page load."""
    defined = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', page))
    # Literal lookups only: `$("step" + n)` is built at runtime and skipped.
    used = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', page))
    missing = sorted(used - defined)
    assert not missing, f"script references ids that are not in the markup: {missing}"


def test_the_revision_comparison_ui_is_gone(page: str) -> None:
    """Revision comparison lives in the CLI and the API, not in the page."""
    for leftover in ("modeDrift", "driftFields", "driftResult", "runDriftDemo", "downloadDrift"):
        assert leftover not in page, f"leftover drift UI reference: {leftover}"


def test_the_page_can_be_pointed_at_a_backend(page: str) -> None:
    """Statically hosted, the page has no API of its own and must say so."""
    assert 'id="apiEndpoint"' in page
    assert "BackendUnavailable" in page
    assert "/api/health" in page
