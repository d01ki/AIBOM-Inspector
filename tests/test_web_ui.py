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


def test_revision_comparison_is_its_own_section(page: str) -> None:
    """Baseline vs candidate is a separate panel over the same diff API.

    An earlier version made drift a *mode* of the scan panel and shared its
    result container; keeping the two apart is what this guards.
    """
    for leftover in ("modeDrift", "driftFields", "driftResult", "runDriftDemo", "downloadDrift"):
        assert leftover not in page, f"leftover mode-based drift UI reference: {leftover}"
    compare = page.index('id="compareSection"')
    results_start = page.index('id="results" tabindex="-1" hidden')
    results_end = page.index('id="helpPanel"')
    assert not results_start < compare < page.index('id="scanResult"'), (
        "the comparison must not live inside the scan result container"
    )
    assert compare < results_end
    assert 'id="compareResult" tabindex="-1" hidden' in page
    assert '$("compareResult").hidden = false;' in page
    # The page renders the engine's verdicts; it does not compute its own.
    assert "/api/diff/demo?" in page and '"/api/diff"' in page
    assert "drift.bom" in page and "security_boundary_changed" in page


def test_the_page_can_be_pointed_at_a_backend(page: str) -> None:
    """Statically hosted, the page has no API of its own and must say so."""
    assert 'id="apiEndpoint"' in page
    assert "BackendUnavailable" in page
    assert "/api/health" in page
