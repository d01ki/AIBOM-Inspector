"""Self-contained HTML report renderer.

No external resources are referenced (CSP-safe, offline-openable). All
entity-derived text is HTML-escaped — the report never trusts scanned content.
"""

from __future__ import annotations

from html import escape

from aibom.inventory import Inventory
from aibom.models.findings import Finding, SecurityScore, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3123b",
    Severity.HIGH: "#d64500",
    Severity.MEDIUM: "#b8860b",
    Severity.LOW: "#3a7d3a",
    Severity.INFO: "#5a6472",
}
_GRADE_COLOR = {"A": "#2e8b57", "B": "#6a9c3a", "C": "#b8860b", "D": "#d64500", "F": "#b3123b"}

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  color: #1c2330; background: #f5f6f8; }
.wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 36px 0 12px; }
.sub { color: #5a6472; margin: 0 0 24px; font-size: 13px; word-break: break-all; }
.cards { display: flex; flex-wrap: wrap; gap: 16px; align-items: stretch; }
.score { flex: 0 0 180px; background: #fff; border-radius: 12px; padding: 20px; text-align: center;
  box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.score .num { font-size: 52px; font-weight: 700; line-height: 1; }
.score .grade { font-size: 14px; color: #5a6472; margin-top: 6px; }
.cats { flex: 1 1 300px; background: #fff; border-radius: 12px; padding: 16px 20px;
  box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.cat { margin: 10px 0; }
.cat .row { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 3px; }
.bar { height: 8px; border-radius: 4px; background: #e6e8ec; overflow: hidden; }
.bar > span { display: block; height: 100%; border-radius: 4px; }
.chips { margin: 16px 0 0; display: flex; flex-wrap: wrap; gap: 8px; }
.chip { font-size: 12px; font-weight: 600; color: #fff; padding: 3px 10px; border-radius: 999px; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px;
  overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
th, td { text-align: left; padding: 10px 12px; font-size: 13px; vertical-align: top;
  border-bottom: 1px solid #eef0f3; }
th { background: #fafbfc; font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
  color: #5a6472; }
tr:last-child td { border-bottom: none; }
.sev { font-weight: 700; color: #fff; padding: 2px 8px; border-radius: 6px; font-size: 11px;
  white-space: nowrap; }
code { background: #eef0f3; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
.rem { color: #3a4453; font-size: 12px; margin-top: 4px; }
.empty { background: #fff; border-radius: 12px; padding: 24px; text-align: center; color: #2e8b57;
  box-shadow: 0 1px 3px rgba(0,0,0,.08); }
footer { margin-top: 40px; color: #8a929e; font-size: 12px; }
"""


def render_html(
    inventory: Inventory, findings: list[Finding], score: SecurityScore
) -> str:
    meta = inventory.metadata
    parts: list[str] = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>AIBOM report — {escape(meta.target)}</title>",
        f"<style>{_CSS}</style></head><body><div class='wrap'>",
        "<h1>AIBOM Inspector report</h1>",
        f"<p class='sub'>{escape(meta.target)} · "
        f"{escape(meta.tool)} {escape(meta.tool_version)} · {escape(meta.created_at)}"
        f"{_stats_suffix(inventory)}</p>",
        # "Nothing found" must not read as a triumphant 100/A.
        _score_cards(score)
        if inventory.entities
        else "<div class='empty'>No AI components detected — nothing to score.</div>",
        _severity_chips(score),
        _findings_section(findings),
        _inventory_section(inventory),
        "<footer>Static, evidence-backed analysis. Scores are computed from deterministic "
        "rules only (no LLM). Each category starts at 100 and loses points per finding "
        "(critical 40 / high 20 / medium 10 / low 3, max 3 findings per rule); overall = "
        "0.55 &times; mean + 0.45 &times; worst category.</footer>",
        "</div></body></html>",
    ]
    return "".join(parts)


def _stats_suffix(inventory: Inventory) -> str:
    st = inventory.stats
    if not st.files_scanned:
        return ""
    parts = f" · read {st.files_scanned} files ({st.bytes_scanned // 1024} KB)"
    if st.duration_ms is not None:
        parts += f" in {st.duration_ms} ms"
    if st.manifests_parsed:
        parts += f" · manifests: {escape(', '.join(st.manifests_parsed))}"
    return parts


def _score_cards(score: SecurityScore) -> str:
    grade = score.grade
    color = _GRADE_COLOR.get(grade, "#5a6472")
    bars: list[str] = []
    for cat in score.categories:
        bar_color = "#2e8b57" if cat.score >= 75 else "#b8860b" if cat.score >= 50 else "#b3123b"
        bars.append(
            "<div class='cat'>"
            f"<div class='row'><span>{escape(cat.category.value)}</span>"
            f"<span>{cat.score} · {cat.finding_count} finding(s)</span></div>"
            "<div class='bar'>"
            f"<span style='width:{cat.score}%;background:{bar_color}'></span></div>"
            "</div>"
        )
    return (
        "<div class='cards'>"
        f"<div class='score'><div class='num' style='color:{color}'>{score.overall}</div>"
        f"<div class='grade'>/ 100 · grade {grade}</div></div>"
        f"<div class='cats'>{''.join(bars)}</div>"
        "</div>"
    )


def _severity_chips(score: SecurityScore) -> str:
    chips: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = score.severity_counts.get(sev.value, 0)
        if n:
            chips.append(
                f"<span class='chip' style='background:{_SEVERITY_COLOR[sev]}'>"
                f"{n} {escape(sev.value)}</span>"
            )
    if not chips:
        return ""
    return f"<div class='chips'>{''.join(chips)}</div>"


def _findings_section(findings: list[Finding]) -> str:
    if not findings:
        return "<h2>Findings</h2><div class='empty'>No risk findings. 🎉</div>"
    rows: list[str] = []
    for f in findings:
        locations = ", ".join(ev.location() for ev in f.source_evidence[:4]) or "—"
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{_SEVERITY_COLOR[f.severity]}'>"
            f"{escape(f.severity.value)}</span></td>"
            f"<td><code>{escape(f.rule_id)}</code></td>"
            f"<td><strong>{escape(f.title)}</strong><br>{escape(f.description)}"
            f"<div class='rem'>Fix: {escape(f.remediation)}</div></td>"
            f"<td>{escape(f.entity_name or '—')}<br><code>{escape(locations)}</code></td>"
            "</tr>"
        )
    return (
        "<h2>Findings</h2><table><thead><tr>"
        "<th>Severity</th><th>Rule</th><th>Finding</th><th>Where</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _inventory_section(inventory: Inventory) -> str:
    rows: list[str] = []
    for entity in sorted(inventory.entities, key=lambda e: (e.type.value, e.name)):
        provider = (
            getattr(entity, "provider", None)
            or getattr(entity, "source", None)
            or getattr(entity, "ecosystem", None)
            or "—"
        )
        loc = entity.source_evidence[0].location() if entity.source_evidence else "—"
        rows.append(
            "<tr>"
            f"<td>{escape(entity.type.value)}</td>"
            f"<td>{escape(entity.name)}</td>"
            f"<td>{escape(str(provider))}</td>"
            f"<td><code>{escape(loc)}</code></td>"
            "</tr>"
        )
    if not rows:
        return "<h2>Inventory</h2><div class='empty'>No AI components discovered.</div>"
    counts = inventory.counts()
    summary = " · ".join(f"{v} {k}" for k, v in counts.items())
    return (
        f"<h2>Inventory <span style='font-size:13px;color:#5a6472'>({escape(summary)})</span></h2>"
        "<table><thead><tr><th>Type</th><th>Name</th><th>Provider/Source</th><th>Evidence</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )
