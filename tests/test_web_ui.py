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

WEB = Path(__file__).resolve().parents[1] / "web"
# The page is markup + one stylesheet + one script, served side by side.
PARTS = ("index.html", "app.css", "app.js")


@pytest.fixture(scope="module")
def page() -> str:
    return "\n".join((WEB / name).read_text(encoding="utf-8") for name in PARTS)


def test_the_page_loads_its_stylesheet_and_script() -> None:
    markup = (WEB / "index.html").read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="app.css">' in markup
    assert '<script src="app.js"></script>' in markup
    assert "<style>" not in markup and "<script>" not in markup


def _results_rule(page: str) -> str:
    """The base ``.results`` declaration block."""
    match = re.search(r"\n\.results \{(.*?)\}", page, re.S)
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


def test_revision_comparison_is_its_own_view(page: str) -> None:
    """Comparing revisions is a separate view over the diff API, not a scan mode.

    An earlier version made drift a *mode* of the scan panel and shared its
    result container; the review then asked for comparison and demos to leave
    the main analysis flow entirely (#43, #46).
    """
    for leftover in ("modeDrift", "driftFields", "driftResult", "runDriftDemo", "downloadDrift",
                     "heroDrift", "heroMcp"):
        assert leftover not in page, f"leftover drift UI reference: {leftover}"
    analyze = page.index('data-view="analyze"')
    compare_view = page.index('data-view="compare"')
    compare = page.index('id="compareSection"')
    assert analyze < page.index('id="scanResult"') < compare_view < compare
    assert 'id="compareView" hidden' in page
    assert 'id="compareResult" tabindex="-1" hidden' in page
    assert '$("compareResult").hidden = false;' in page
    # The page renders the engine's verdicts; it does not compute its own.
    assert "/api/diff/demo?" in page and '"/api/diff"' in page
    assert "drift.bom" in page and "security_boundary_changed" in page
    assert "agent_privileges" in page


def test_demos_are_labelled_and_never_claim_to_verify_user_code(page: str) -> None:
    assert "Examples with bundled data" in page and "demo-badge" in page
    assert "Bundled fixed revision" in page
    assert "gates CI" not in page, "say what fails CI (--fail-on), not that the demo gates it"
    assert "Same AIBOM" not in page
    assert "Compared components identical" in page


def test_the_page_talks_only_to_the_server_that_served_it(page: str) -> None:
    """The page and the API are one server; there is no backend to choose.

    A "Backend address" field and a ``?api=`` link used to let the page send
    the repository URL to, and draw results from, any server a link named. It
    only mattered for a statically hosted copy of the page, which is no longer
    published.
    """
    script = (WEB / "app.js").read_text(encoding="utf-8")
    for leftover in ("apiEndpoint", "apiOverride", "apiBase", "localStorage", 'get("api")',
                     "BackendUnavailable"):
        assert leftover not in page, f"leftover backend-selection code: {leftover}"
    # One function talks to the network, and it is only ever given a path.
    assert len(re.findall(r"(?<![A-Za-z.])fetch\(", script)) == 1
    assert not re.search(r"""["'`]https?://[^"'`]*/api/""", script)
    assert "/api/health" in page


def test_the_page_can_be_translated_but_identifiers_stay_verbatim(page: str) -> None:
    """Browser translation works on the prose and leaves evidence alone.

    The whole page used to opt out (``translate="no"`` on ``<html>`` plus the
    ``notranslate`` meta), so a reader could not translate it at all. The
    opt-out now sits on what must read exactly as it does in the repository:
    package names, file paths, rule ids, versions and the graphs.
    """
    markup = (WEB / "index.html").read_text(encoding="utf-8")
    script = (WEB / "app.js").read_text(encoding="utf-8")
    assert '<html lang="en">' in markup
    assert "notranslate" not in page
    # Every <code> and graph is marked as it is rendered, in one place.
    assert 'const VERBATIM = "code, pre, svg";' in script
    assert "MutationObserver" in script and 'setAttribute("translate", "no")' in script
    # Names that are not in <code> carry the attribute themselves.
    for marked in ('id="resultRepoName" translate="no"', 'class="brand-name" translate="no"',
                   '<td translate="no">${esc(e.name)}</td>',
                   '<strong translate="no">${esc(p.name)}</strong>'):
        assert marked in page, f"identifier left open to translation: {marked}"


def test_findings_lead_and_the_score_is_secondary(page: str) -> None:
    """The headline comes from the worst finding (API `headline`), not the grade (#36)."""
    tabs = re.findall(r'class="result-tab" data-tab="(\w+)"', page)
    assert tabs[0] == "findings"
    assert {"deps", "graph", "agent", "inventory", "compliance"} <= set(tabs)
    assert 'selectTab((d.findings || []).length ? "findings" : "deps")' in page
    assert "d.headline" in page
    # The hygiene score lives in a collapsed, explicitly secondary disclosure.
    assert '<details class="disclosure score-box" id="overview">' in page
    assert "Supply-chain hygiene score (secondary)" in page


def test_agent_paths_distinguish_not_detected_from_not_evaluated(page: str) -> None:
    for state in ("not_detected", "not_evaluated", "failed", "evaluated"):
        assert f'"{state}"' in page
    assert '$("agentTab").hidden = state.state === "not_detected";' in page
    # The page renders the analyzer's verdicts and unknowns; it does not compute its own.
    assert "capability_paths" in page and "unknowns" in page
    assert '"/api/agent-drift/demo?scenario="' in page


def test_dependencies_tab_renders_the_full_table_and_says_when_relations_are_unknown(
    page: str,
) -> None:
    assert 'id="depsSection" data-panel="deps"' in page
    assert "d.dependencies" in page and "relations_resolved" in page
    assert "Dependency relations unresolved" in page


def _stage_ids() -> set[str]:
    script = (WEB / "app.js").read_text(encoding="utf-8")
    stages = re.search(r"const STAGES = \{(.*?)\};", script, re.S)
    assert stages, "STAGES table not found in app.js"
    return set(re.findall(r"^  (\w+):", stages.group(1), re.M))


def test_stream_stages_match_the_backend() -> None:
    """The UI labels exactly the stage ids the server can send."""
    root = WEB.parent / "src" / "aibom"
    backend = set(re.findall(r'report\("(\w+)"\)',
                             (root / "service.py").read_text(encoding="utf-8")
                             + (root / "server" / "app.py").read_text(encoding="utf-8")))
    assert _stage_ids() == backend


def test_the_scan_reads_the_stage_stream() -> None:
    """The page ships with its server, so there is no older API to fall back to."""
    script = (WEB / "app.js").read_text(encoding="utf-8")
    assert '"/api/scan/stream"' in script
    assert "NO_STREAM" not in script and '"/api/scan"' not in script
    assert 'id="progressSteps"' in (WEB / "index.html").read_text(encoding="utf-8")
