"""``aibom`` command-line interface (M1: scan + inventory output).

Static analysis only — running ``aibom scan`` never executes the target code.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from aibom import __version__
from aibom.collectors.repo import RepoCollector
from aibom.export.cyclonedx import to_cyclonedx_json
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import EntityType
from aibom.models.findings import Finding, SecurityScore, Severity
from aibom.report.html import render_html
from aibom.resolvers.huggingface import HFClient, HuggingFaceResolver
from aibom.risk.engine import evaluate as evaluate_risk
from aibom.risk.scoring import score_findings


def _make_output_encode_safe() -> None:
    """Never crash on a legacy console codepage (e.g. Windows cp932).

    Keeps the console's native encoding but swaps the error handler to
    ``replace`` so characters it cannot encode degrade gracefully instead of
    raising ``UnicodeEncodeError``.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):  # stream-dependent
                reconfigure(errors="replace")


_make_output_encode_safe()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="AIBOM Inspector - discover & inventory AI supply chains (static, evidence-backed).",
)
console = Console()

_TYPE_STYLE = {
    EntityType.MODEL: "bold cyan",
    EntityType.DATASET: "bold magenta",
    EntityType.PROMPT: "bold yellow",
    EntityType.AGENT: "bold green",
    EntityType.SERVICE: "bold blue",
    EntityType.LICENSE: "white",
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "green",
    Severity.INFO: "dim",
}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"aibom {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: Annotated[
        bool | None,
        typer.Option(
            "--version", "-V", callback=_version_callback, is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """AIBOM Inspector CLI."""


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Repository or directory to scan.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the full inventory as JSON to this path."),
    ] = None,
    cyclonedx: Annotated[
        Path | None,
        typer.Option(
            "--cyclonedx", "-c", help="Write a CycloneDX 1.6 (ML-BOM) AIBOM to this path."
        ),
    ] = None,
    resolve: Annotated[
        bool,
        typer.Option(
            "--resolve/--no-resolve",
            help="Enrich Hugging Face models/datasets via the hub API (network).",
        ),
    ] = False,
    hf_cache: Annotated[
        Path | None,
        typer.Option("--hf-cache", help="Directory for cached HF metadata (offline snapshots)."),
    ] = None,
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Write a self-contained HTML report to this path."),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if any finding is at/above this severity "
            "(info|low|medium|high|critical).",
        ),
    ] = None,
    min_confidence: Annotated[
        float,
        typer.Option("--min-confidence", help="Drop entities whose best evidence is below this."),
    ] = 0.0,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress the summary tables.")
    ] = False,
) -> None:
    """Statically scan TARGET for AI supply-chain components and build an inventory."""
    if not target.exists():
        console.print(f"[red]error:[/red] target does not exist: {target}")
        raise typer.Exit(code=2)

    fail_threshold = _parse_severity(fail_on)

    inventory = Inventory(
        metadata=ScanMetadata(tool_version=__version__, target=str(target.resolve()))
    )
    RepoCollector(target).collect(inventory)

    if resolve or hf_cache is not None:
        client = HFClient(cache_dir=hf_cache, offline=not resolve)
        HuggingFaceResolver(client).resolve(inventory)

    _apply_confidence_filter(inventory, min_confidence)

    findings = evaluate_risk(inventory)
    score = score_findings(findings)

    if not quiet:
        _render(inventory)
        _render_risk(findings, score)

    if output is not None:
        output.write_text(inventory.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]written[/green] inventory to [bold]{output}[/bold]")

    if cyclonedx is not None:
        cyclonedx.write_text(to_cyclonedx_json(inventory), encoding="utf-8")
        console.print(f"[green]written[/green] CycloneDX AIBOM to [bold]{cyclonedx}[/bold]")

    if report is not None:
        report.write_text(render_html(inventory, findings, score), encoding="utf-8")
        console.print(f"[green]written[/green] HTML report to [bold]{report}[/bold]")

    if fail_threshold is not None and any(
        f.severity.rank >= fail_threshold.rank for f in findings
    ):
        raise typer.Exit(code=1)


def _parse_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        console.print(f"[red]error:[/red] invalid --fail-on '{value}'. Choose one of: {valid}")
        raise typer.Exit(code=2) from None


def _apply_confidence_filter(inventory: Inventory, threshold: float) -> None:
    if threshold <= 0.0:
        return
    keep = [
        e for e in inventory.entities
        if any(ev.confidence >= threshold for ev in e.source_evidence)
    ]
    kept_ids = {e.id for e in keep}
    inventory.entities = keep
    inventory.relationships = [
        r for r in inventory.relationships
        if r.source_id in kept_ids and r.target_id in kept_ids
    ]


def _render(inventory: Inventory) -> None:
    counts = inventory.counts()
    summary = Table(title="AI supply-chain inventory", title_style="bold", show_edge=True)
    summary.add_column("Component", style="bold")
    summary.add_column("Count", justify="right")
    for etype in EntityType:
        if counts.get(etype.value):
            summary.add_row(
                f"[{_TYPE_STYLE[etype]}]{etype.value}[/]", str(counts[etype.value])
            )
    summary.add_row("[dim]relationships[/dim]", str(len(inventory.relationships)))
    console.print(summary)

    if not inventory.entities:
        console.print("[yellow]No AI components discovered.[/yellow]")
        return

    detail = Table(title="Discovered components", show_lines=False)
    detail.add_column("Type", style="bold")
    detail.add_column("Name")
    detail.add_column("Provider/Source", style="dim")
    detail.add_column("Evidence", style="dim")
    for entity in sorted(inventory.entities, key=lambda e: (e.type.value, e.name)):
        provider = getattr(entity, "provider", None) or getattr(entity, "source", None) or ""
        ev = entity.source_evidence[0].location() if entity.source_evidence else ""
        detail.add_row(
            f"[{_TYPE_STYLE[entity.type]}]{entity.type.value}[/]", entity.name, provider, ev
        )
    console.print(detail)


def _render_risk(findings: list[Finding], score: SecurityScore) -> None:
    cats = "  ".join(f"{c.category.value} {c.score}" for c in score.categories)
    grade_style = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    console.print(
        f"\n[bold]Security score:[/bold] "
        f"[{grade_style.get(score.grade, 'white')}]{score.overall}/100 "
        f"(grade {score.grade})[/]   [dim]{cats}[/dim]"
    )

    if not findings:
        console.print("[green]No risk findings.[/green]")
        return

    table = Table(title="Risk findings", show_lines=False)
    table.add_column("Sev", style="bold")
    table.add_column("Rule")
    table.add_column("Finding")
    table.add_column("Where", style="dim")
    for f in findings:
        loc = f.source_evidence[0].location() if f.source_evidence else ""
        where = f"{f.entity_name} @ {loc}" if f.entity_name else loc
        table.add_row(
            f"[{_SEVERITY_STYLE[f.severity]}] {f.severity.value} [/]",
            f.rule_id,
            f.title,
            where,
        )
    console.print(table)


if __name__ == "__main__":
    app()
