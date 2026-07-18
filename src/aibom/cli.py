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
from aibom.config import ConfigError, ScanConfig, load_config
from aibom.export.cyclonedx import to_cyclonedx_json
from aibom.export.sarif import to_sarif_json
from aibom.inventory import Inventory
from aibom.models.entities import EntityType
from aibom.models.findings import Finding, SecurityScore, Severity
from aibom.report.html import render_html
from aibom.service import ScanResult, run_scan


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
    EntityType.PACKAGE: "bold white",
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
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """AIBOM Inspector CLI."""


@app.command()
def scan(
    target: Annotated[
        str | None,
        typer.Argument(
            help="Local path or public repo URL (https://github.com/owner/repo). "
            "Omit it to be prompted interactively.",
        ),
    ] = None,
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
    vulns: Annotated[
        bool | None,
        typer.Option(
            "--vulns/--no-vulns",
            help="Map pinned dependencies to known vulnerabilities via OSV (network). "
            "Defaults to following --resolve.",
        ),
    ] = None,
    hf_cache: Annotated[
        Path | None,
        typer.Option("--hf-cache", help="Directory for cached HF metadata (offline snapshots)."),
    ] = None,
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Write a self-contained HTML report to this path."),
    ] = None,
    sarif: Annotated[
        Path | None,
        typer.Option(
            "--sarif",
            help="Write findings as SARIF 2.1.0 (GitHub Code Scanning) to this path.",
        ),
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
        float | None,
        typer.Option("--min-confidence", help="Drop entities whose best evidence is below this."),
    ] = None,
    disable_detector: Annotated[
        list[str] | None,
        typer.Option(
            "--disable-detector",
            help="Disable a detector by stable ID; repeat the option to disable several.",
        ),
    ] = None,
    ignore_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--ignore-rule",
            help="Suppress findings by rule ID ('TDR-004', or a family like 'OSV-*'); "
            "repeatable. Suppressed findings are excluded from the score and --fail-on.",
        ),
    ] = None,
    no_config: Annotated[
        bool,
        typer.Option(
            "--no-config",
            help="Ignore aibom.toml / [tool.aibom] in the target; use flags only.",
        ),
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress the summary tables.")
    ] = False,
) -> None:
    """Statically scan TARGET for AI supply-chain components and build an inventory.

    TARGET is a local path or a public repository URL (shallow-cloned into a
    temp dir and cleaned up afterwards). With no TARGET on an interactive
    terminal, you are prompted for one.

    Defaults for --fail-on, --min-confidence, --disable-detector, and
    --ignore-rule are read from a local target's aibom.toml (or [tool.aibom] in
    its pyproject.toml); explicit flags override the config. URL targets never
    contribute config — a scanned third-party repo can't set your policy.
    """
    if target is None:
        target = _prompt_for_target()

    is_url = target.lower().startswith(("http://", "https://"))
    local_path = Path(target)
    if not is_url and not local_path.exists():
        console.print(f"[red]error:[/red] target does not exist: {target}")
        raise typer.Exit(code=2)

    config = (
        ScanConfig() if (no_config or is_url) else _load_config_or_exit(local_path)
    )

    fail_threshold = _parse_severity(fail_on) if fail_on is not None else config.fail_on
    effective_min_confidence = (
        min_confidence if min_confidence is not None else config.min_confidence
    )
    disabled = set(config.disable_detectors) | set(disable_detector or [])
    ignore_rules = config.ignore_rules + [
        r for r in (ignore_rule or []) if r not in config.ignore_rules
    ]

    def _scan(path: Path, display: str | None = None) -> ScanResult:
        return run_scan(
            path,
            resolve=resolve,
            vulns=vulns,
            hf_cache=hf_cache,
            min_confidence=effective_min_confidence,
            disabled_detectors=disabled,
            ignore_rules=ignore_rules,
            display_target=display,
        )

    if is_url:
        from aibom.server.clone import CloneError, clone_repo

        try:
            with (
                console.status(f"cloning (shallow) and scanning {target} ..."),
                clone_repo(target) as cloned,
            ):
                result = _scan(cloned, display=target)
        except CloneError as exc:
            console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from None
    else:
        result = _scan(local_path)
    inventory, findings, score = result.inventory, result.findings, result.score

    if not quiet:
        _render(inventory)
        if inventory.has_ai_components():
            _render_risk(findings, score)
        else:
            n_deps = len(inventory.by_type(EntityType.PACKAGE))
            extra = f" ({n_deps} non-AI dependencies catalogued)" if n_deps else ""
            console.print(f"[dim]Nothing to score: no AI components were detected{extra}.[/dim]")
        st = inventory.stats
        manifests = f" · manifests: {', '.join(st.manifests_parsed)}" if st.manifests_parsed else ""
        console.print(
            f"[dim]Read {st.files_scanned} files ({st.bytes_scanned // 1024} KB) "
            f"in {st.duration_ms} ms{manifests}[/dim]"
        )

    if output is not None:
        _write_or_exit(output, inventory.model_dump_json(indent=2), "inventory")

    if cyclonedx is not None:
        _write_or_exit(cyclonedx, to_cyclonedx_json(inventory), "CycloneDX AIBOM")

    if report is not None:
        _write_or_exit(report, render_html(inventory, findings, score), "HTML report")

    if sarif is not None:
        _write_or_exit(sarif, to_sarif_json(findings), "SARIF log")

    if fail_threshold is not None and any(f.severity.rank >= fail_threshold.rank for f in findings):
        raise typer.Exit(code=1)


def _stdin_is_tty() -> bool:
    """Split out so tests can force the interactive path."""
    return sys.stdin.isatty()


def _prompt_for_target() -> str:
    """Guided entry: ask what to scan when no TARGET argument was given."""
    if not _stdin_is_tty():
        console.print(
            "[red]error:[/red] no scan target given. "
            "Pass a local path or a public repo URL, e.g.:\n"
            "  aibom scan .\n"
            "  aibom scan https://github.com/owner/repo"
        )
        raise typer.Exit(code=2)
    console.print("[bold]What should I scan?[/bold]")
    console.print(
        "[dim]A local directory (e.g. '.') or a public repository URL "
        "(e.g. https://github.com/owner/repo)[/dim]"
    )
    value = str(typer.prompt("Scan target")).strip()
    if not value:
        console.print("[red]error:[/red] empty target")
        raise typer.Exit(code=2)
    return value


def _parse_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        console.print(f"[red]error:[/red] invalid --fail-on '{value}'. Choose one of: {valid}")
        raise typer.Exit(code=2) from None


def _write_or_exit(path: Path, content: str, label: str) -> None:
    """Write an artifact, turning OS errors into a clean exit instead of a traceback."""
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]error:[/red] cannot write {label} to '{path}': {exc.strerror or exc}")
        raise typer.Exit(code=2) from None
    console.print(f"[green]written[/green] {label} to [bold]{path}[/bold]")


def _load_config_or_exit(target: Path) -> ScanConfig:
    try:
        return load_config(target)
    except ConfigError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from None


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on.")] = 8000,
) -> None:
    """Run the HTTP API + web UI (requires the 'server' extra)."""
    try:
        import uvicorn
    except ModuleNotFoundError:
        console.print(
            "[red]error:[/red] the server extra is not installed. "
            "Install it with [bold]pip install 'aibom[server]'[/bold]."
        )
        raise typer.Exit(code=2) from None

    console.print(f"AIBOM Inspector API on [bold]http://{host}:{port}[/bold]  (Ctrl-C to stop)")
    uvicorn.run("aibom.server.app:app", host=host, port=port, log_level="info")


def _render(inventory: Inventory) -> None:
    counts = inventory.counts()
    summary = Table(title="AI supply-chain inventory", title_style="bold", show_edge=True)
    summary.add_column("Component", style="bold")
    summary.add_column("Count", justify="right")
    for etype in EntityType:
        if counts.get(etype.value):
            summary.add_row(f"[{_TYPE_STYLE[etype]}]{etype.value}[/]", str(counts[etype.value]))
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
    for entity in sorted(
        inventory.entities,
        key=lambda e: (e.type.value, not getattr(e, "ai", False), e.name),
    ):
        provider = (
            getattr(entity, "provider", None)
            or getattr(entity, "source", None)
            or getattr(entity, "ecosystem", None)
            or ""
        )
        if getattr(entity, "ai", False):
            provider = f"{provider} [bold cyan]· AI[/bold cyan]" if provider else "AI"
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
