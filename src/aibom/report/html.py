"""Self-contained HTML report renderer.

No external resources are referenced (CSP-safe, offline-openable). All
entity-derived text is HTML-escaped — the report never trusts scanned content.
"""

from __future__ import annotations

from html import escape
from math import cos, pi, sin

from aibom.graph import build_graph
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
.wrap { max-width: 1200px; margin: 0 auto; padding: 32px 20px 64px; }
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
.graph-card { margin: 0; padding: 18px; overflow-x: auto; background: #fff; border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.graph-card svg { display: block; width: 100%; min-width: 640px; height: auto; }
.graph-edge { stroke: #9aa3b2; stroke-width: 1.5; stroke-opacity: .55; }
.graph-node circle { stroke: #fff; stroke-width: 2.5; }
.graph-node text { fill: #263142; font-size: 12px; font-weight: 600; }
.graph-legend { display: flex; flex-wrap: wrap; gap: 8px 16px; margin: 12px 0 0;
  color: #5a6472; font-size: 12px; }
.graph-legend span { display: inline-flex; align-items: center; gap: 6px; }
.graph-legend i { width: 10px; height: 10px; border-radius: 50%; }
footer { margin-top: 40px; color: #8a929e; font-size: 12px; }
"""

_TYPE_COLOR = {
    "model": "#3a6ea5",
    "dataset": "#7a5ea5",
    "prompt": "#9c7a2e",
    "agent": "#2e7d5b",
    "service": "#556070",
    "package": "#8a6d3b",
    "license": "#667085",
}


def render_html(inventory: Inventory, findings: list[Finding], score: SecurityScore) -> str:
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
        if inventory.has_ai_components()
        else "<div class='empty'>No AI components detected — nothing to score.</div>",
        _severity_chips(score),
        _findings_section(findings),
        _graph_section(inventory, findings),
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
        flow = ""
        if f.source_kind or f.sink_kind:
            flow = (
                "<div class='rem'>Flow: "
                f"{escape(f.source_kind or 'unknown')} &rarr; "
                f"{escape(f.sink_kind or 'unknown')}</div>"
            )
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{_SEVERITY_COLOR[f.severity]}'>"
            f"{escape(f.severity.value)}</span></td>"
            f"<td><code>{escape(f.rule_id)}</code></td>"
            f"<td><strong>{escape(f.title)}</strong><br>{escape(f.description)}"
            f"{flow}"
            f"<div class='rem'>Fix: {escape(f.remediation)}</div></td>"
            f"<td>{escape(f.entity_name or '—')}<br><code>{escape(locations)}</code></td>"
            "</tr>"
        )
    return (
        "<h2>Findings</h2><table><thead><tr>"
        "<th>Severity</th><th>Rule</th><th>Finding</th><th>Where</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _graph_section(inventory: Inventory, findings: list[Finding]) -> str:
    graph = build_graph(inventory, findings)
    nodes = graph["nodes"]
    if not nodes:
        return "<h2>Dependency context</h2><div class='empty'>No components to graph.</div>"

    width = 900
    height = 460 if len(nodes) > 1 else 300
    center_x, center_y = width / 2, height / 2
    positions: dict[str, tuple[float, float]] = {}
    if len(nodes) == 1:
        positions[nodes[0]["id"]] = (center_x, center_y)
    else:
        radius = min(330, 130 + len(nodes) * 8)
        for index, node in enumerate(nodes):
            angle = -pi / 2 + 2 * pi * index / len(nodes)
            positions[node["id"]] = (
                center_x + radius * cos(angle),
                center_y + min(radius, 170) * sin(angle),
            )

    edges: list[str] = []
    for edge in graph["edges"]:
        source = positions.get(edge["source"])
        target = positions.get(edge["target"])
        if source is None or target is None:
            continue
        edges.append(
            "<line class='graph-edge' "
            f"x1='{source[0]:.1f}' y1='{source[1]:.1f}' "
            f"x2='{target[0]:.1f}' y2='{target[1]:.1f}'>"
            f"<title>{escape(edge['type'])}</title></line>"
        )

    node_markup: list[str] = []
    for node in nodes:
        x, y = positions[node["id"]]
        severity = node.get("severity")
        color = (
            _SEVERITY_COLOR[Severity(severity)]
            if severity is not None
            else _TYPE_COLOR.get(node["type"], "#6b7280")
        )
        full_label = str(node["label"])
        label = full_label if len(full_label) <= 20 else f"{full_label[:19]}…"
        detail = f"{full_label} · {node['type']}"
        if severity:
            detail += f" · {severity} severity"
        if node.get("location"):
            detail += f" · {node['location']}"
        delta_x, delta_y = x - center_x, y - center_y
        if abs(delta_x) > abs(delta_y) * 0.4:
            label_x = x + (18 if delta_x > 0 else -18)
            label_y = y + 4
            anchor = "start" if delta_x > 0 else "end"
        else:
            label_x = x
            label_y = y + (30 if delta_y >= 0 else -18)
            anchor = "middle"
        node_markup.append(
            f"<g class='graph-node'><title>{escape(detail)}</title>"
            f"<circle cx='{x:.1f}' cy='{y:.1f}' r='11' fill='{color}'></circle>"
            f"<text x='{label_x:.1f}' y='{label_y:.1f}' text-anchor='{anchor}'>"
            f"{escape(label)}</text></g>"
        )

    legend_items = [
        ("#b3123b", "critical"),
        ("#d64500", "high"),
        ("#b8860b", "medium"),
        ("#3a7d3a", "low"),
        ("#6b7280", "no finding"),
    ]
    legend = "".join(
        f"<span><i style='background:{color}'></i>{label}</span>"
        for color, label in legend_items
    )
    return (
        "<h2>Dependency context</h2>"
        "<figure class='graph-card'>"
        f"<svg viewBox='0 0 {width} {height}' role='img' "
        "aria-labelledby='graph-title graph-description'>"
        "<title id='graph-title'>AI dependency graph</title>"
        "<desc id='graph-description'>Components and their detected relationships. "
        "Node colors indicate the highest related finding severity.</desc>"
        f"{''.join(edges)}{''.join(node_markup)}</svg>"
        f"<figcaption class='graph-legend'>{legend}</figcaption>"
        "</figure>"
    )


def _inventory_section(inventory: Inventory) -> str:
    rows: list[str] = []
    for entity in sorted(inventory.entities, key=lambda e: (e.type.value, e.name)):
        provider = (
            getattr(entity, "provider", None)
            or getattr(entity, "source", None)
            or getattr(entity, "source_kind", None)
            or getattr(entity, "ecosystem", None)
            or "—"
        )
        loc = entity.source_evidence[0].location() if entity.source_evidence else "—"
        confidence = max((ev.confidence for ev in entity.source_evidence), default=0.0)
        contexts = ", ".join(sorted(item.value for item in entity.source_contexts)) or "—"
        detectors = ", ".join(sorted(entity.detector_ids)) or "—"
        rows.append(
            "<tr>"
            f"<td>{escape(entity.type.value)}</td>"
            f"<td>{escape(entity.name)}</td>"
            f"<td>{escape(str(provider))}</td>"
            f"<td>{escape(_usage_label(entity))}</td>"
            f"<td>{escape(contexts)}</td>"
            f"<td>{confidence:.2f}</td>"
            f"<td><code>{escape(loc)}</code><br>{escape(detectors)}</td>"
            "</tr>"
        )
    if not rows:
        return "<h2>Inventory</h2><div class='empty'>No AI components discovered.</div>"
    counts = inventory.counts()
    summary = " · ".join(f"{v} {k}" for k, v in counts.items())
    return (
        f"<h2>Inventory <span style='font-size:13px;color:#5a6472'>({escape(summary)})</span></h2>"
        "<table><thead><tr><th>Type</th><th>Name</th><th>Provider/Source</th>"
        "<th>Usage</th><th>Context</th><th>Confidence</th><th>Evidence / Detector</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _usage_label(entity: object) -> str:
    usage = getattr(entity, "usage", None)
    if usage is None:
        return "—"
    states = [
        name
        for name in ("declared", "imported", "instantiated", "invoked")
        if bool(getattr(usage, name, False))
    ]
    states.append(f"reachable:{usage.reachable.value}")
    return " → ".join(states)
