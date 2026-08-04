"""``aibom`` command-line interface (M1: scan + inventory output).

Static analysis only — running ``aibom scan`` never executes the target code.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from aibom import __version__
from aibom.compliance.minimum_elements import (
    ElementOrigin,
    ElementStatus,
    MinimumElementsReport,
    UnsupportedDocument,
    evaluate_cyclonedx,
)
from aibom.config import ConfigError, ScanConfig, load_config
from aibom.demo import drift_demo_paths, impact_demo_path, ts_drift_demo_paths
from aibom.drift import DriftReport, compare_scan_results
from aibom.export.cyclonedx import (
    DEFAULT_LIFECYCLE,
    LIFECYCLE_PHASES,
    SbomContext,
    to_cyclonedx,
    to_cyclonedx_json,
)
from aibom.export.sarif import to_sarif_json
from aibom.impact import ImpactPath, build_impact_paths
from aibom.inventory import Inventory
from aibom.models.entities import EntityType
from aibom.models.findings import Finding, SecurityScore, Severity
from aibom.policy import production_view
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
    no_args_is_help=False,
    help="AIBOM Inspector - discover & inventory AI supply chains (static, evidence-backed). "
    "Run with no arguments on a terminal for a guided menu.",
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


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
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
    """AIBOM Inspector CLI. Run with no arguments for a guided menu."""
    if ctx.invoked_subcommand is not None:
        return
    if _stdin_is_tty():
        _menu()
    else:
        console.print(ctx.get_help())


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
    minimum_elements: Annotated[
        Path | None,
        typer.Option(
            "--minimum-elements",
            help="Write the CISA 2026 SBOM minimum-elements conformance report as JSON.",
        ),
    ] = None,
    sbom_author: Annotated[
        str | None,
        typer.Option(
            "--sbom-author",
            help="Entity authoring the SBOM data (CISA 2026 'SBOM Author').",
        ),
    ] = None,
    sbom_supplier: Annotated[
        str | None,
        typer.Option(
            "--sbom-supplier",
            help="Entity producing the scanned software (CISA 2026 'Component Producer').",
        ),
    ] = None,
    sbom_lifecycle: Annotated[
        str | None,
        typer.Option(
            "--sbom-lifecycle",
            help="Lifecycle phase the SBOM is generated in (CISA 2026 'SBOM Generation "
            f"Context'): {' | '.join(LIFECYCLE_PHASES)}. Default: pre-build.",
        ),
    ] = None,
    lockfiles: Annotated[
        bool | None,
        typer.Option(
            "--lockfiles/--no-lockfiles",
            help="Resolve lockfiles for transitive components and artifact digests "
            "(CISA 2026 coverage + Component Hash). Default: on.",
        ),
    ] = None,
    no_config: Annotated[
        bool,
        typer.Option(
            "--no-config",
            help="Ignore aibom.toml / [tool.aibom] in the target; use flags only.",
        ),
    ] = False,
    demo: Annotated[
        bool,
        typer.Option(
            "--demo",
            help="Scan the bundled deliberately-vulnerable demo app (offline, no setup).",
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
    if demo:
        demo_dir = _demo_path()
        if demo_dir is None:
            console.print("[red]error:[/red] the demo app is not bundled in this installation")
            raise typer.Exit(code=2)
        console.print(f"[dim]demo: scanning the bundled vulnerable AI app at {demo_dir}[/dim]")
        target = str(demo_dir)
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
    use_lockfiles = lockfiles if lockfiles is not None else config.lockfiles
    sbom_context = _sbom_context(config, sbom_author, sbom_supplier, sbom_lifecycle)

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
            lockfiles=use_lockfiles,
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
        if production_view(inventory).has_ai_components():
            # Same ordering as the web UI: blast radius first, then findings.
            _render_impacts(build_impact_paths(inventory), empty_note=False)
            _render_risk(findings, score)
        else:
            n_deps = len(inventory.by_type(EntityType.PACKAGE))
            extra = f" ({n_deps} non-AI dependencies catalogued)" if n_deps else ""
            console.print(
                "[dim]Nothing to score: no production AI components were detected"
                f"{extra}. Test/example/docs components remain in the inventory.[/dim]"
            )
        st = inventory.stats
        manifests = f" · manifests: {', '.join(st.manifests_parsed)}" if st.manifests_parsed else ""
        console.print(
            f"[dim]Read {st.files_scanned} files ({st.bytes_scanned // 1024} KB) "
            f"in {st.duration_ms} ms{manifests}[/dim]"
        )
        production_inventory = production_view(inventory)
        excluded = len(inventory.entities) - len(production_inventory.entities)
        if excluded:
            console.print(
                f"[dim]Risk scope: production · {excluded} test/example/docs "
                "component(s) remain in inventory but are excluded from findings, "
                "score, and graph.[/dim]"
            )

    if not quiet or minimum_elements is not None:
        elements = evaluate_cyclonedx(to_cyclonedx(inventory, context=sbom_context))
        if not quiet:
            _render_minimum_elements(elements)
        if minimum_elements is not None:
            _write_or_exit(
                minimum_elements,
                json.dumps(elements.to_dict(), indent=2, ensure_ascii=False),
                "SBOM minimum-elements report",
            )

    if output is not None:
        _write_or_exit(output, inventory.model_dump_json(indent=2), "inventory")

    if cyclonedx is not None:
        _write_or_exit(
            cyclonedx,
            to_cyclonedx_json(inventory, context=sbom_context),
            "CycloneDX AIBOM",
        )

    if report is not None:
        _write_or_exit(
            report,
            render_html(inventory, findings, score, sbom_context=sbom_context),
            "HTML report",
        )

    if sarif is not None:
        _write_or_exit(sarif, to_sarif_json(findings), "SARIF log")

    if fail_threshold is not None and any(f.severity.rank >= fail_threshold.rank for f in findings):
        raise typer.Exit(code=1)


def _stdin_is_tty() -> bool:
    """Split out so tests can force the interactive path."""
    return sys.stdin.isatty()


def _output_dir() -> Path:
    """Where interactive runs drop artifacts.

    In the container the source tree is mounted read-only at ``/work``, so
    ``AIBOM_OUTPUT_DIR`` points at the writable ``/out`` bind mount. Outside
    Docker this is just the current directory.
    """
    configured = os.environ.get("AIBOM_OUTPUT_DIR")
    if configured:
        candidate = Path(configured)
        if candidate.is_dir() and os.access(candidate, os.W_OK):
            return candidate
    return Path()


def _demo_path() -> Path | None:
    """Locate the bundled deliberately-vulnerable demo app, if shipped."""
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "demo_app",  # installed wheel / Docker image
        here.parents[2] / "tests" / "fixtures" / "vulnerable-ai-app",  # source checkout
    ]
    for candidate in candidates:
        if (candidate / "requirements.txt").is_file():
            return candidate
    return None


def _menu() -> None:
    """Numbered top-level menu shown when `aibom` runs with no arguments."""
    console.print()
    console.print(
        "[bold]AIBOM Inspector[/bold] - AI supply-chain scanner (static, evidence-backed)"
    )
    console.print()
    console.print("  [bold]1[/bold]) Impact demo - input to agent tool blast radius (offline)")
    console.print("  [bold]2[/bold]) Scan a public repository URL")
    console.print("  [bold]3[/bold]) Scan a local directory")
    console.print("  [bold]4[/bold]) Compare two revisions (behavioral drift)")
    console.print("  [bold]5[/bold]) Start the web UI in your browser")
    console.print("  [bold]q[/bold]) Quit")
    console.print()
    valid = {"1", "2", "3", "4", "5", "q", "quit", "exit"}
    while True:
        choice = str(typer.prompt("Choose", default="1")).strip().lower()
        if choice in valid:
            break
        console.print("[yellow]Please answer 1, 2, 3, 4, 5, or q.[/yellow]")
    if choice in {"q", "quit", "exit"}:
        raise typer.Exit()
    if choice == "5":
        serve()
        return
    if choice == "1":
        demo()
        return
    if choice == "4":
        baseline = Path(str(typer.prompt("Baseline directory")).strip())
        candidate = Path(str(typer.prompt("Candidate directory")).strip())
        diff_scans(baseline=baseline, candidate=candidate)
        return
    if choice == "2":
        target: str | None = str(
            typer.prompt("Repository URL (e.g. https://github.com/owner/repo)")
        ).strip()
    else:
        target = str(typer.prompt("Local directory to scan", default=".")).strip()

    report: Path | None = None
    if typer.confirm("Save a self-contained HTML report?", default=False):
        report = _output_dir() / "report.html"
    scan(target=target, report=report)
    if report is not None:
        console.print(f"[dim]Open {report} in your browser to view the report.[/dim]")


@app.command()
def demo() -> None:
    """Run the offline impact + behavioral-drift talk demo."""
    impact_dir = impact_demo_path()
    if impact_dir is None:
        console.print("[red]error:[/red] the impact demo is not bundled in this installation")
        raise typer.Exit(code=2)

    console.print(
        "\n[bold]Impact demo[/bold] - code-proven input -> instructions -> bound tool -> operation"
    )
    console.print("[dim]Static analysis only; the fixture is never imported or executed.[/dim]")
    result = run_scan(impact_dir, display_target="built-in://impact-demo")
    paths = build_impact_paths(result.inventory)
    _render_impacts(paths)
    _render_risk(result.findings, result.score)

    for language, revisions in (
        ("Python", drift_demo_paths()),
        ("TypeScript", ts_drift_demo_paths()),
    ):
        if revisions is None:
            continue
        baseline, candidate = revisions
        console.print(
            f"\n[bold]Behavioral drift demo ({language})[/bold] - same model and tool, "
            "new command-execution blast radius"
        )
        slug = language.lower()
        drift_report = compare_scan_results(
            run_scan(baseline, display_target=f"built-in://drift/{slug}/baseline"),
            run_scan(candidate, display_target=f"built-in://drift/{slug}/candidate"),
        )
        _render_drift(drift_report)


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


@app.command("diff")
def diff_scans(
    baseline: Annotated[
        Path,
        typer.Argument(help="Baseline repository or source directory."),
    ],
    candidate: Annotated[
        Path,
        typer.Argument(help="Candidate repository or source directory."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the full drift report as JSON."),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero for drift at/above this severity "
            "(info|low|medium|high|critical).",
        ),
    ] = None,
    min_confidence: Annotated[
        float,
        typer.Option(
            "--min-confidence",
            help="Apply the same evidence-confidence floor to both scans.",
        ),
    ] = 0.0,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress the drift summary table."),
    ] = False,
) -> None:
    """Compare two AIBOM scans, including trust-boundary and usage drift.

    Unlike a component-only BOM diff, this detects a prompt becoming exposed to
    untrusted input even when both revisions use exactly the same SDK and model.
    Prompt bodies are never written to the report; static content is represented
    only by hashes.
    """
    for label, path in (("baseline", baseline), ("candidate", candidate)):
        if not path.exists():
            console.print(f"[red]error:[/red] {label} target does not exist: {path}")
            raise typer.Exit(code=2)
    if not 0.0 <= min_confidence <= 1.0:
        console.print("[red]error:[/red] --min-confidence must be between 0 and 1")
        raise typer.Exit(code=2)

    threshold = _parse_severity(fail_on)
    baseline_result = run_scan(baseline, min_confidence=min_confidence)
    candidate_result = run_scan(candidate, min_confidence=min_confidence)
    report = compare_scan_results(baseline_result, candidate_result)

    if not quiet:
        _render_drift(report)
    if output is not None:
        _write_or_exit(output, report.model_dump_json(indent=2), "AIBOM drift report")
    if threshold is not None and any(
        change.severity.rank >= threshold.rank for change in report.changes
    ):
        raise typer.Exit(code=1)


@app.command()
def conformance(
    sbom: Annotated[
        Path,
        typer.Argument(help="CycloneDX JSON SBOM to check (any generator, not just this one)."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the conformance report as JSON."),
    ] = None,
    fail_on_missing: Annotated[
        bool,
        typer.Option(
            "--fail-on-missing",
            help="Exit non-zero if any minimum element is silently missing "
            "(a declared known unknown is not a failure).",
        ),
    ] = False,
) -> None:
    """Check a CycloneDX SBOM against the CISA 2026 SBOM minimum elements.

    The 2026 baseline replaces the 2021 NTIA minimum elements and applies to all
    software, AI systems included. Data the generator could not know conforms
    when it is *declared* — a silent gap does not.
    """
    if not sbom.is_file():
        console.print(f"[red]error:[/red] no such file: {sbom}")
        raise typer.Exit(code=2)
    try:
        doc = json.loads(sbom.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        console.print(f"[red]error:[/red] cannot read {sbom}: {exc}")
        raise typer.Exit(code=2) from None
    try:
        report = evaluate_cyclonedx(doc)
    except UnsupportedDocument as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from None

    _render_minimum_elements(report, detailed=True)
    if output is not None:
        _write_or_exit(
            output,
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            "SBOM minimum-elements report",
        )
    if fail_on_missing and not report.conformant:
        raise typer.Exit(code=1)


@app.command()
def serve(
    host: Annotated[
        str | None,
        typer.Option("--host", help="Bind address (default: AIBOM_HOST env or 127.0.0.1)."),
    ] = None,
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

    # The Docker image sets AIBOM_HOST=0.0.0.0 so menu option 4 / bare `serve`
    # is reachable through the published port, not just inside the container.
    bind = host or os.environ.get("AIBOM_HOST") or "127.0.0.1"
    shown = "localhost" if bind in {"0.0.0.0", "127.0.0.1"} else bind
    console.print(
        f"AIBOM Inspector web UI + API -- open [bold]http://{shown}:{port}[/bold] "
        "in your browser  (Ctrl-C to stop)"
    )
    uvicorn.run("aibom.server.app:app", host=bind, port=port, log_level="info")


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
    highest = max(findings, key=lambda item: item.severity.rank).severity if findings else None
    severity_note = (
        f"; {highest.value} finding present"
        if highest in {Severity.CRITICAL, Severity.HIGH}
        else ""
    )
    console.print(
        f"\n[bold]Security score:[/bold] "
        f"[{grade_style.get(score.grade, 'white')}]{score.overall}/100 "
        f"(grade {score.grade}{severity_note})[/]   [dim]{cats}[/dim]"
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


def _sbom_context(
    config: ScanConfig,
    author: str | None,
    supplier: str | None,
    lifecycle: str | None,
) -> SbomContext:
    """Merge SBOM authorship from flags (winning) and config."""
    phase = lifecycle or config.sbom_lifecycle
    if phase is not None and phase not in LIFECYCLE_PHASES:
        console.print(
            f"[red]error:[/red] invalid --sbom-lifecycle '{phase}'. "
            f"Choose one of: {', '.join(LIFECYCLE_PHASES)}"
        )
        raise typer.Exit(code=2)
    return SbomContext(
        author=author or config.sbom_author,
        author_email=config.sbom_author_email,
        supplier=supplier or config.sbom_supplier,
        lifecycle=phase or DEFAULT_LIFECYCLE,
    )


_ELEMENT_STYLE = {
    ElementStatus.SATISFIED: "green",
    ElementStatus.PARTIAL: "yellow",
    ElementStatus.DECLARED_UNKNOWN: "cyan",
    ElementStatus.MISSING: "bold red",
}

_ELEMENT_LABEL = {
    ElementStatus.SATISFIED: "ok",
    ElementStatus.PARTIAL: "partial",
    ElementStatus.DECLARED_UNKNOWN: "declared",
    ElementStatus.MISSING: "MISSING",
}

_ORIGIN_LABEL = {
    ElementOrigin.CARRIED_OVER: "2021",
    ElementOrigin.UPDATED_2026: "2026 upd",
    ElementOrigin.NEW_2026: "2026 new",
}


def _render_minimum_elements(report: MinimumElementsReport, *, detailed: bool = False) -> None:
    """One summary line during a scan; the full table for `aibom conformance`."""
    verdict = (
        "[green]conformant — every gap is declared[/green]"
        if report.conformant
        else f"[bold red]{report.missing} element(s) silently missing[/bold red]"
    )
    console.print(
        f"\n[bold]CISA 2026 SBOM minimum elements:[/bold] {verdict}\n"
        f"[dim]{report.satisfied} satisfied · {report.partial} partial · "
        f"{report.declared_unknown} declared unknown · {report.missing} missing "
        f"of {len(report.elements)} elements[/dim]"
    )
    if not detailed:
        if not report.conformant:
            console.print(
                "[dim]Run `aibom conformance <sbom.json>` for the per-element table.[/dim]"
            )
        return

    table = Table(title="Minimum elements", show_lines=False)
    table.add_column("Status", style="bold")
    table.add_column("Element")
    table.add_column("Since", style="dim")
    table.add_column("Coverage", justify="right")
    table.add_column("Where", style="dim")
    for element in report.elements:
        coverage = (
            f"{element.present}/{element.applicable}"
            if element.applicable > 1
            else ("yes" if element.present else "no")
        )
        if element.declared_unknown:
            coverage += f" (+{element.declared_unknown} declared)"
        table.add_row(
            f"[{_ELEMENT_STYLE[element.status]}]{_ELEMENT_LABEL[element.status]}[/]",
            element.name,
            _ORIGIN_LABEL[element.origin],
            coverage,
            element.cyclonedx_path,
        )
    console.print(table)

    for element in report.elements:
        if element.status is ElementStatus.MISSING:
            examples = ", ".join(element.undeclared_gaps[:5])
            suffix = f" [dim]({examples})[/dim]" if examples else ""
            console.print(f"[red]missing[/red] {element.name}: {element.remediation}{suffix}")
    console.print(
        f"[dim]{report.components} component(s), {report.transitive_components} transitive · "
        f"{report.document_format}[/dim]"
    )


def _render_drift(report: DriftReport) -> None:
    console.print(
        f"\n[bold]AIBOM behavioral drift:[/bold] {len(report.changes)} change(s)\n"
        f"[dim]{report.baseline_target} -> {report.candidate_target}[/dim]"
    )
    if not report.changes:
        console.print("[green]No AI supply-chain or trust-boundary drift detected.[/green]")
        return

    table = Table(title="Security-significant changes", show_lines=False)
    table.add_column("Sev", style="bold")
    table.add_column("Kind")
    table.add_column("Change")
    table.add_column("Evidence", style="dim")
    for change in report.changes:
        evidence = change.after_evidence or change.before_evidence
        location = evidence[0].location() if evidence else ""
        table.add_row(
            f"[{_SEVERITY_STYLE[change.severity]}] {change.severity.value} [/]",
            change.kind.value,
            f"{change.title}\n[dim]{change.description}[/dim]",
            location,
        )
    console.print(table)


def _render_impacts(paths: list[ImpactPath], *, empty_note: bool = True) -> None:
    if not paths:
        if empty_note:
            console.print("[yellow]No strongly linked agent capability path detected.[/yellow]")
        return
    table = Table(title="Potential blast radius (direct bindings only)", show_lines=True)
    table.add_column("Sev", style="bold")
    table.add_column("Proven path")
    table.add_column("Potential consequence")
    table.add_column("Evidence", style="dim")
    for path in paths:
        models = ", ".join(path.model_names) or "unresolved model"
        route = (
            f"{path.source_kind} -> privileged instructions -> {models} -> "
            f"{', '.join(path.tool_names)}"
        )
        capability_evidence = [
            evidence
            for capability in path.capabilities
            for evidence in capability.source_evidence
        ]
        locations = ", ".join(item.location() for item in capability_evidence)
        table.add_row(
            f"[{_SEVERITY_STYLE[path.severity]}] {path.severity.value} [/]",
            route,
            path.consequence,
            locations,
        )
    console.print(table)
    console.print(
        "[dim]Meaning: attacker steering is plausible from static code links; "
        "runtime exploit success is not claimed.[/dim]"
    )


if __name__ == "__main__":
    app()
