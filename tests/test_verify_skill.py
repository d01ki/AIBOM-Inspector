"""The verify skill is a deliverable too: its metadata and eval cases are tested.

The mechanical half of each eval case (which features a change maps to) is
checked against the real feature map, so the skill's examples cannot drift from
what ``scripts/verify.py`` actually does.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.test_feature_map import FEATURES, verify

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".claude" / "skills" / "verify" / "SKILL.md"
CASES = json.loads(
    (SKILL.parent / "evals" / "cases.json").read_text(encoding="utf-8")
)["cases"]


def _frontmatter() -> dict[str, str]:
    text = SKILL.read_text(encoding="utf-8")
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert match, "SKILL.md must start with YAML frontmatter"
    fields = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def test_frontmatter_names_and_describes_the_skill() -> None:
    fm = _frontmatter()
    assert fm["name"] == "verify"
    # Claude Code truncates description + when_to_use at 1,536 characters.
    assert 0 < len(fm["description"]) + len(fm.get("when_to_use", "")) <= 1536


def test_skill_states_the_four_statuses_and_the_never_pass_rule() -> None:
    text = SKILL.read_text(encoding="utf-8")
    for status in ("PASS", "FAIL", "BLOCKED", "NOT RUN"):
        assert f"| {status} |" in text
    assert "Never report a check you did not run as PASS" in text


def test_skill_statuses_match_the_script() -> None:
    assert verify.STATUSES == ("PASS", "FAIL", "BLOCKED", "NOT RUN")


def test_skill_links_resolve() -> None:
    text = SKILL.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
        if target.startswith("http"):
            continue
        assert (SKILL.parent / target).resolve().exists(), target


def test_cases_are_well_formed() -> None:
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids))
    for case in CASES:
        assert case["situation"] and case["must"] and case["must_not"], case["id"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_case_mapping_matches_the_feature_map(case: dict) -> None:
    hit, unmapped = verify.map_files(case["changed_files"], FEATURES)
    assert sorted(f.id for f in hit) == sorted(case["expect_features"])
    if "expect_unmapped" in case:
        assert unmapped == case["expect_unmapped"]
