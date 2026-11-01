"""Terminal rendering for agent-security reports and privilege drift."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from aibom.agent_security.models import AgentSecurityReport, PrivilegeDriftReport, Verdict

_VERDICT_STYLE = {
    Verdict.POTENTIALLY_ALLOWED: "yellow",
    Verdict.EXPLICITLY_DENIED: "green",
    Verdict.NO_MATCHING_ALLOW: "green",
    Verdict.UNKNOWN: "magenta",
}
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render_report(console: Console, report: AgentSecurityReport) -> None:
    console.print(
        f"\n[bold]Agent capability paths[/bold] [dim]({report.target}; "
        f"schema {report.schema_version}; identity-policy-only, not effective AWS "
        "authorization)[/dim]"
    )
    if not report.capability_paths:
        console.print("[dim]No agent -> tool -> cloud operation paths were found.[/dim]")
    else:
        table = Table(show_lines=False)
        for column in ("Agent", "Identity", "Tool", "Action", "Resource", "Verdict"):
            table.add_column(column)
        for path in report.capability_paths:
            style = _VERDICT_STYLE.get(path.verdict, "")
            table.add_row(
                path.agent_id,
                path.identity_id or "[magenta]unmapped[/magenta]",
                path.tool_name + (" [dim](mcp)[/dim]" if path.via == "mcp" else ""),
                path.action,
                path.resource,
                f"[{style}]{path.verdict.value}[/{style}]",
            )
        console.print(table)
    names = {tool.tool_id: tool for server in report.mcp_servers for tool in server.tools}
    for server in report.mcp_servers:
        clients = sorted({c.client_ref for c in report.mcp_connections if c.server_id == server.id})
        console.print(
            f"  mcp server {server.name or server.id} ({server.file}, {server.status}): "
            f"tools {[t.name for t in server.tools]}; clients {clients or 'none'}; "
            f"runs as {server.identity_id or '[magenta]unmapped[/magenta]'}"
        )
    for agent in report.agents:
        if agent.mcp_tool_ids:
            exposed = []
            for tool_id in agent.mcp_tool_ids:
                tool = names.get(tool_id)
                label = tool.name if tool else tool_id
                if tool and tool.capability_kinds:
                    label += f" [{','.join(tool.capability_kinds)}]"
                exposed.append(label)
            console.print(f"  {agent.id} exposed MCP tools: {', '.join(exposed)}")
    for delegation in report.delegations:
        child = delegation.child_id or f"[magenta]unresolved[/magenta] ({delegation.child_ref})"
        reachable = [
            p
            for p in report.delegate_paths
            if p.parent_id == delegation.parent_id
            and p.child_id == delegation.child_id
            and p.mechanism == delegation.mechanism
        ]
        allowed = sorted(
            {p.action for p in reachable if p.child_verdict is Verdict.POTENTIALLY_ALLOWED}
        )
        console.print(
            f"  delegation: {delegation.parent_id} -{delegation.mechanism}-> {child}; "
            f"child potentially allowed: {allowed or 'none'} "
            "[dim](not merged into the parent; guards unverified)[/dim]"
        )
    if report.scope.registry is not None:
        unregistered = [a.id for a in report.agents if a.management_status == "unregistered"]
        console.print(
            f"  registry {report.scope.registry}: "
            + (
                f"[yellow]unregistered: {', '.join(unregistered)}[/yellow]"
                if unregistered
                else "[green]all agents registered[/green]"
            )
        )
    if report.unknowns:
        console.print(
            f"[magenta]{len(report.unknowns)} unknown(s)[/magenta] (not treated as safe):"
        )
        for item in report.unknowns[:10]:
            console.print(f"  [magenta]?[/magenta] {item.subject}: {item.reason}")


def render_drift(console: Console, report: PrivilegeDriftReport) -> None:
    if report.bom_components_unchanged is None:
        bom = "unknown"
    elif report.bom_components_unchanged:
        bom = "[green]unchanged[/green]"
    else:
        bom = "[red]changed[/red]"

    drift = "[red]yes[/red]" if report.security_drift else "[green]no[/green]"
    console.print(
        f"\n[bold]Agent privilege drift[/bold] {report.baseline} -> {report.candidate}\n"
        f"  1) AI-BOM components: {bom}    security drift: {drift}"
    )
    for note in report.scope_mismatch:
        console.print(f"  [magenta]scope mismatch:[/magenta] {note}")
    if not report.changes:
        console.print("  [green]No privilege changes.[/green]")
    for change in report.changes:
        style = _SEVERITY_STYLE.get(change.severity, "")
        subject = change.agent or change.identity or "-"
        console.print(
            f"  [{style}]{change.severity.upper():8}[/{style}] {change.type} "
            f"[bold]{subject}[/bold] {change.action or ''} {change.affected_resource or ''}"
        )
        if change.before or change.after:
            console.print(f"           2) path: {change.before} -> {change.after}")
        if change.evidence:
            policy_refs = [ref for ref in change.evidence if "#/" in ref]
            code_refs = [ref for ref in change.evidence if "#/" not in ref]
            if policy_refs:
                console.print(f"           3) policy: {', '.join(policy_refs)}")
            if code_refs:
                console.print(f"              code: {', '.join(code_refs)}")
        console.print(
            f"           4) certainty: {change.certainty} ({change.change_status}); "
            + "; ".join(change.severity_reasons)
        )
        if change.remediation is not None:
            console.print(f"           5) fix: {change.remediation.recommended_actions[0]}")
            console.print(f"           6) retest: {change.remediation.retest_command}")
    console.print(
        f"  [dim]unknowns: baseline {report.unknowns_baseline}, "
        f"candidate {report.unknowns_candidate}[/dim]"
    )
