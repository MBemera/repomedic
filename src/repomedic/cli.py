"""Typer CLI for repomedic.

Agent-first design rules:
- Never prompt unless --interactive is passed. Defaults just work.
- Machine outputs (json/markdown-to-stdout) keep stdout pure; progress and
  status go to stderr.
- Exit codes are meaningful: 0 clean, 1 findings at/above --fail-on, 2 usage.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Optional  # noqa: UP035

import click
import typer
from rich.console import Console
from rich.panel import Panel
from typer.core import TyperGroup

from repomedic.analyzers import get_all_analyzers
from repomedic.core.fingerprint import assign_fingerprints
from repomedic.core.scanner import AnalyzerEventFn
from repomedic.core.service import (
    ScanOutcome,
    ScanRequest,
    ScanServiceError,
    run_scan,
)
from repomedic.models import AnalyzerResult, ScanReport
from repomedic.output.json_output import print_json
from repomedic.output.markdown_output import generate_fix_report, render_fix_report
from repomedic.output.rich_output import print_rich


class DefaultScanGroup(TyperGroup):
    """Click group that routes bare paths/flags to the `scan` command.

    Makes `repomedic .` and `repomedic --output json src/` behave as
    `repomedic scan ...` while keeping normal subcommand dispatch
    (`repomedic sniff .`) intact. With no arguments at all on an
    interactive terminal, it routes to the `menu` launcher instead —
    piped and scripted invocations still scan, so agents never see a prompt.
    """

    default_command = "scan"

    def parse_args(self, ctx, args: list[str]) -> list[str]:  # noqa: ANN001 — click Context (vendored in typer)
        from repomedic.commands.menu import stdio_is_interactive

        if not args and stdio_is_interactive():
            return super().parse_args(ctx, ["menu"])
        has_command = any(not a.startswith("-") and a in self.commands for a in args)
        if not has_command:
            non_options = [a for a in args if not a.startswith("-")]
            wants_group_help = not non_options and any(
                a in ("--help", "-h") for a in args
            )
            if not wants_group_help:
                args = [self.default_command, *args]
        return super().parse_args(ctx, args)


app = typer.Typer(
    name="repomedic",
    cls=DefaultScanGroup,
    help=(
        "Agent-first repo bug sniffer — diagnose issues in folders and repos, "
        "hand the fixes to a coding agent. Run `repomedic agents` for the agent guide. "
        "Bare `repomedic [PATH]` is shorthand for `repomedic scan [PATH]`; "
        "with no arguments on a terminal it opens the interactive menu."
    ),
    no_args_is_help=False,
)

console = Console()
err_console = Console(stderr=True)

STDOUT_SENTINEL = "-"
RUNTIME_OUTPUTS = {"json", "rich", "markdown", "md"}


def _resolve_dir(target: str) -> Path:
    """Resolve a plain directory target (no GitHub URLs), exit 2 if invalid."""
    path = Path(target).resolve()
    if not path.is_dir():
        err_console.print(f"[red]Error:[/] {target} is not a directory")
        raise typer.Exit(2)
    return path


def _pick_analyzers() -> list[str] | None:
    """Interactive analyzer picker. Returns list of names or None for all."""
    all_analyzers = get_all_analyzers()

    console.print(Panel("[bold]Select analyzers to run[/]", border_style="cyan"))
    console.print("  [bold green]0[/]  All analyzers")
    for i, a in enumerate(all_analyzers, 1):
        console.print(f"  [bold green]{i}[/]  {a.name:<16} {a.description}")
    console.print()

    raw = console.input(
        "[bold]Enter numbers separated by spaces[/] (default: 0 = all): "
    ).strip()

    if not raw or raw == "0":
        return None  # all

    selected: list[str] = []
    for token in raw.split():
        try:
            idx = int(token)
        except ValueError:
            # Treat as analyzer name
            if token in {a.name for a in all_analyzers}:
                selected.append(token)
            continue
        if 1 <= idx <= len(all_analyzers):
            selected.append(all_analyzers[idx - 1].name)

    if not selected:
        return None
    return selected


def _execute_runtime_command(
    script: str,
    args: list[str],
    *,
    output: str,
    debug_enabled: bool,
    timeout: int,
    max_frames: int,
    max_variables: int,
) -> None:
    """Execute one runtime command and emit its versioned scan report."""
    from repomedic.analyzers.runtime import RuntimeAnalyzer
    from repomedic.debug.session import CaptureBounds

    _validate_runtime_output(output)
    script_path = _resolve_script(script)
    try:
        bounds = CaptureBounds(
            max_frames=max_frames,
            max_variables_per_frame=max_variables,
        )
    except ValueError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(2) from exc

    result = RuntimeAnalyzer().analyze_script(
        str(script_path),
        cwd=str(script_path.parent),
        args=args,
        debug=debug_enabled,
        bounds=bounds,
        timeout=timeout,
    )
    report = _runtime_report(result, script_path.parent)
    _render_runtime_report(report, output)
    if result.error:
        err_console.print(f"[red]Could not run script:[/] {result.error}")
    raise typer.Exit(1 if report.summary.errors or result.error else 0)


def _validate_runtime_output(output: str) -> None:
    if output in RUNTIME_OUTPUTS:
        return
    choices = ", ".join(sorted(RUNTIME_OUTPUTS - {"md"}))
    err_console.print(
        f"[red]Error:[/] invalid --output '{output}' (choose from: {choices})"
    )
    raise typer.Exit(2)


def _resolve_script(script: str) -> Path:
    script_path = Path(script).resolve()
    if script_path.is_file():
        return script_path
    err_console.print(f"[red]Error:[/] {script} is not a file")
    raise typer.Exit(2)


def _runtime_report(result: AnalyzerResult, target: Path) -> ScanReport:
    assign_fingerprints([result], target)
    report = ScanReport(target=str(target), results=[result])
    report.build_summary()
    return report


def _render_runtime_report(report: ScanReport, output: str) -> None:
    if output == "rich":
        print_rich(report, console)
        return
    if output in ("markdown", "md"):
        typer.echo(render_fix_report(report))
        return
    typer.echo(print_json(report))


def _execute_scan(
    target: str,
    *,
    output: str,
    analyzers: Optional[str],
    interactive: bool,
    min_severity: Optional[str],
    report_file: Optional[str],
    changed: bool,
    since: Optional[str],
    max_findings: Optional[int],
    fail_on: Optional[str],
    snippets: bool,
    analyzer_timeout: Optional[float] = None,
    allow_exec: Optional[bool] = None,
    baseline: Optional[str] = None,
    no_baseline: bool = False,
) -> None:
    """CLI shell around the scan service: flags in, rendered output + exit code out."""
    if output not in {"rich", "json", "markdown", "md", "sarif"}:
        err_console.print(
            f"[red]Error:[/] invalid --output '{output}' (choose from: rich, json, markdown, sarif)"
        )
        raise typer.Exit(2)

    # The interactive analyzer picker is a human affordance, so it lives in
    # the CLI layer — the service itself never prompts.
    analyzer_list: list[str] | None = None
    if analyzers:
        analyzer_list = [a.strip() for a in analyzers.split(",")]
    elif interactive:
        analyzer_list = _pick_analyzers()

    progress = console if output == "rich" else err_console

    request = ScanRequest(
        target=target,
        analyzers=analyzer_list,
        min_severity=min_severity,
        changed=changed,
        since=since,
        max_findings=max_findings,
        fail_on=fail_on,
        analyzer_timeout=analyzer_timeout,
        allow_exec=allow_exec,
        baseline=baseline,
        use_baseline=not no_baseline,
    )

    outcome: ScanOutcome | None = None
    try:
        with _analyzer_progress(rich_ui=output == "rich") as on_analyzer:
            outcome = run_scan(
                request,
                progress=lambda msg: progress.print(f"[cyan]{msg}[/]"),
                on_analyzer=on_analyzer,
            )
        _render_scan(outcome, output=output, report_file=report_file, snippets=snippets)
        raise typer.Exit(outcome.exit_code)
    except ScanServiceError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(exc.exit_code) from exc
    finally:
        if outcome is not None:
            outcome.cleanup()


@contextmanager
def _analyzer_progress(*, rich_ui: bool) -> Iterator[AnalyzerEventFn]:
    """Live per-analyzer progress so long scans are never a silent wait.

    Rich mode shows a spinner/bar with the analyzers currently running;
    machine outputs (json/markdown/sarif) get one dim tick line per
    finished analyzer on stderr, keeping stdout pure.
    """
    if not rich_ui:

        def on_stderr_event(event: str, name: str, completed: int, total: int) -> None:
            if event == "done":
                err_console.print(f"[dim]  ✓ {name} ({completed}/{total})[/]")
            elif event == "timeout":
                err_console.print(f"[yellow]  ⏱ {name} timed out ({completed}/{total})[/]")

        yield on_stderr_event
        return

    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    # "point" reads as a heart-monitor blip — on brand, and visually
    # distinct from the braille-dots spinner other CLIs use.
    progress_ui = Progress(
        SpinnerColumn(spinner_name="point", style="bold green"),
        TextColumn("[bold cyan]🩺 analyzers[/]"),
        BarColumn(complete_style="green", finished_style="bold green"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[running]}[/]"),
        console=console,
        transient=True,
    )
    task_id = progress_ui.add_task("analyzers", total=None, running="")
    running: set[str] = set()

    def on_rich_event(event: str, name: str, completed: int, total: int) -> None:
        # "start" arrives from worker threads; rich's internal lock makes
        # concurrent task updates safe.
        if event == "start":
            running.add(name)
        else:
            running.discard(name)
        progress_ui.update(
            task_id, total=total, completed=completed, running=", ".join(sorted(running))
        )

    with progress_ui:
        yield on_rich_event


def _render_scan(
    outcome: ScanOutcome, *, output: str, report_file: Optional[str], snippets: bool
) -> None:
    """Route a finished scan to the chosen output format."""
    report = outcome.report
    if output == "json":
        typer.echo(print_json(report))
    elif output == "sarif":
        from repomedic.output.sarif_output import print_sarif

        typer.echo(print_sarif(report))
    elif output in ("markdown", "md"):
        if report_file == STDOUT_SENTINEL:
            typer.echo(render_fix_report(report, include_snippets=snippets))
        else:
            if report_file:
                report_path = Path(report_file)
            elif outcome.was_remote:
                report_path = Path.cwd() / "repomedic-fixes.md"
            else:
                report_path = None
            result_path = generate_fix_report(
                report, report_path, include_snippets=snippets
            )
            err_console.print(
                f"[bold green]✓[/] Fix report written to [cyan]{result_path}[/]"
            )
            err_console.print(
                "  Feed this file to your coding agent for minimal-context fixes."
            )
    else:
        print_rich(report, console)
        if report.findings:
            console.print()
            console.print(
                "[dim]Tip: `repomedic sniff .` prints an agent-ready fix report; "
                "`--output markdown` writes it to a file.[/dim]"
            )


@app.command()
def scan(
    target: str = typer.Argument(".", help="Local path or GitHub URL to scan"),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich, json, markdown, or sarif"
    ),
    all_analyzers: bool = typer.Option(
        False,
        "--all",
        "-A",
        help="Run all analyzers (the default; kept for compatibility)",
    ),
    analyzers: Optional[str] = typer.Option(
        None, "--analyzers", "-a", help="Comma-separated analyzer names"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Pick analyzers interactively"
    ),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity", "-s", help="Minimum severity: error, warning, info"
    ),
    report_file: Optional[str] = typer.Option(
        None,
        "--report-file",
        "-r",
        help="Markdown report path ('-' = stdout; default: <target>/repomedic-fixes.md)",
    ),
    changed: bool = typer.Option(
        False, "--changed", help="Only report findings in git-changed files"
    ),
    since: Optional[str] = typer.Option(
        None, "--since", help="Only report findings in files changed since this git ref"
    ),
    max_findings: Optional[int] = typer.Option(
        None,
        "--max-findings",
        help="Keep only the N most severe findings (0 = unlimited)",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 when findings at/above: error, warning, any, never (default: never)",
    ),
    snippets: bool = typer.Option(
        True,
        "--snippets/--no-snippets",
        help="Include code snippets in markdown reports",
    ),
    analyzer_timeout: Optional[float] = typer.Option(
        None,
        "--analyzer-timeout",
        help="Seconds before an analyzer is abandoned (default 120; 0 = no limit)",
    ),
    allow_exec: Optional[bool] = typer.Option(
        None,
        "--exec/--no-exec",
        help="Allow checks that execute repo code (cargo/go build, eslint). Default: on for local paths, off for URLs",
    ),
    baseline: Optional[str] = typer.Option(
        None,
        "--baseline",
        help="Baseline file of accepted fingerprints (default: auto-detect .repomedic-baseline.json)",
    ),
    no_baseline: bool = typer.Option(
        False, "--no-baseline", help="Ignore any baseline file — report all findings"
    ),
) -> None:
    """Scan a local folder or GitHub repo for issues (all analyzers, no prompts)."""
    _execute_scan(
        target,
        output=output,
        analyzers=analyzers,
        interactive=interactive,
        min_severity=min_severity,
        report_file=report_file,
        changed=changed,
        since=since,
        max_findings=max_findings,
        fail_on=fail_on,
        snippets=snippets,
        analyzer_timeout=analyzer_timeout,
        allow_exec=allow_exec,
        baseline=baseline,
        no_baseline=no_baseline,
    )


@app.command()
def sniff(
    target: str = typer.Argument(".", help="Local path or GitHub URL to scan"),
    output: str = typer.Option(
        "markdown",
        "--output",
        "-o",
        help="Output format: markdown (default), json, or sarif",
    ),
    analyzers: Optional[str] = typer.Option(
        None, "--analyzers", "-a", help="Comma-separated analyzer names"
    ),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity", "-s", help="Minimum severity: error, warning, info"
    ),
    changed: bool = typer.Option(
        False, "--changed", help="Only report findings in git-changed files"
    ),
    since: Optional[str] = typer.Option(
        None, "--since", help="Only report findings in files changed since this git ref"
    ),
    max_findings: Optional[int] = typer.Option(
        None,
        "--max-findings",
        help="Keep only the N most severe findings (default 50; 0 = unlimited)",
    ),
    fail_on: Optional[str] = typer.Option(
        "error",
        "--fail-on",
        help="Exit 1 when findings at/above: error, warning, any, never",
    ),
    report_file: Optional[str] = typer.Option(
        STDOUT_SENTINEL,
        "--report-file",
        "-r",
        help="Markdown report path (default '-' = stdout)",
    ),
    snippets: bool = typer.Option(
        True, "--snippets/--no-snippets", help="Include code snippets"
    ),
    analyzer_timeout: Optional[float] = typer.Option(
        None,
        "--analyzer-timeout",
        help="Seconds before an analyzer is abandoned (default 120; 0 = no limit)",
    ),
    allow_exec: Optional[bool] = typer.Option(
        None,
        "--exec/--no-exec",
        help="Allow checks that execute repo code (cargo/go build, eslint). Default: on for local paths, off for URLs",
    ),
    baseline: Optional[str] = typer.Option(
        None,
        "--baseline",
        help="Baseline file of accepted fingerprints (default: auto-detect .repomedic-baseline.json)",
    ),
    no_baseline: bool = typer.Option(
        False, "--no-baseline", help="Ignore any baseline file — report all findings"
    ),
) -> None:
    """Bug-sniff a repo for agents: markdown fix report on stdout, exit 1 on errors."""
    _execute_scan(
        target,
        output=output,
        analyzers=analyzers,
        interactive=False,
        min_severity=min_severity,
        report_file=report_file,
        changed=changed,
        since=since,
        max_findings=max_findings if max_findings is not None else 50,
        fail_on=fail_on,
        snippets=snippets,
        analyzer_timeout=analyzer_timeout,
        allow_exec=allow_exec,
        baseline=baseline,
        no_baseline=no_baseline,
    )


@app.command()
def run(
    script: str = typer.Argument(
        ..., help="Script to run (py, js, sh, rb, php, pl, lua)"
    ),
    args: Optional[list[str]] = typer.Argument(
        None, help="Arguments passed to the script"
    ),
    output: str = typer.Option(
        "json", "--output", "-o", help="Output format: json, rich, or markdown"
    ),
    debug_enabled: bool = typer.Option(
        False,
        "--debug",
        help="Capture Python crashes with the debugger (other languages keep traceback parsing)",
    ),
    timeout: int = typer.Option(
        30, "--timeout", min=1, max=3600, help="Whole-script timeout in seconds"
    ),
    max_frames: int = typer.Option(
        20, "--max-frames", min=1, max=100, help="Maximum debugger frames to retain"
    ),
    max_variables: int = typer.Option(
        25,
        "--max-vars",
        min=1,
        max=200,
        help="Maximum local variables per debugger frame",
    ),
) -> None:
    """Run a script with the matching interpreter and analyze its failure."""
    _execute_runtime_command(
        script,
        args or [],
        output=output,
        debug_enabled=debug_enabled,
        timeout=timeout,
        max_frames=max_frames,
        max_variables=max_variables,
    )


@app.command("debug")
def debug_script(
    script: str = typer.Argument(
        ...,
        help="Python script to capture (other languages use existing runtime parsing)",
    ),
    args: Optional[list[str]] = typer.Argument(
        None, help="Arguments passed to the script"
    ),
    timeout: int = typer.Option(
        60,
        "--timeout",
        min=1,
        max=3600,
        help="Whole debugger-session timeout in seconds",
    ),
    max_frames: int = typer.Option(
        20, "--max-frames", min=1, max=100, help="Maximum debugger frames to retain"
    ),
    max_variables: int = typer.Option(
        25,
        "--max-vars",
        min=1,
        max=200,
        help="Maximum local variables per debugger frame",
    ),
    output: str = typer.Option(
        "json", "--output", "-o", help="Output format: json, rich, or markdown"
    ),
) -> None:
    """Capture an uncaught Python exception with debugger frames and locals."""
    _execute_runtime_command(
        script,
        args or [],
        output=output,
        debug_enabled=True,
        timeout=timeout,
        max_frames=max_frames,
        max_variables=max_variables,
    )


@app.command()
def baseline(
    target: str = typer.Argument(".", help="Local path to snapshot"),
    file: Optional[str] = typer.Option(
        None,
        "--file",
        "-f",
        help="Baseline file path (default: <target>/.repomedic-baseline.json)",
    ),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich or json"
    ),
) -> None:
    """Accept all current findings: write their fingerprints to a baseline file.

    Later scans drop baselined findings, so `--fail-on error` only trips on
    NEW errors. Re-run this command to re-accept after intentional changes.
    """
    from repomedic.core.baseline import BASELINE_FILENAME, write_baseline

    path = _resolve_dir(target)
    request = ScanRequest(
        target=str(path),
        max_findings=0,
        fail_on="never",
        use_baseline=False,
    )
    try:
        outcome = run_scan(
            request, progress=lambda msg: err_console.print(f"[cyan]{msg}[/]")
        )
    except ScanServiceError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(exc.exit_code) from exc

    baseline_path = Path(file) if file else path / BASELINE_FILENAME
    baseline_model = write_baseline(outcome.report, baseline_path)

    if output == "json":
        typer.echo(baseline_model.model_dump_json(indent=2))
    else:
        console.print(
            f"[bold green]✓[/] Baseline written to [cyan]{baseline_path}[/] "
            f"({len(baseline_model.fingerprints)} accepted fingerprints)"
        )
        console.print(
            "  Future scans report only NEW findings; pass --no-baseline to see everything."
        )


@app.command("list-analyzers")
def list_analyzers(
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich or json"
    ),
) -> None:
    """List all available analyzers."""
    from repomedic.models_commands import AnalyzerInfo, AnalyzerList

    analyzers = get_all_analyzers()
    if output == "json":
        payload = AnalyzerList(
            analyzers=[
                AnalyzerInfo(name=a.name, description=a.description) for a in analyzers
            ]
        )
        typer.echo(payload.model_dump_json(indent=2))
        return
    for a in analyzers:
        console.print(f"  [bold]{a.name}[/] — {a.description}")


@app.command()
def fix(
    target: str = typer.Argument(".", help="Local path to fix"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Preview fixes without changing anything"
    ),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich or json"
    ),
) -> None:
    """Auto-fix common issues (ruff, .gitignore, .env.example)."""
    path = _resolve_dir(target)

    from repomedic.commands.fix import collect_fixes, render_fixes
    from repomedic.models_commands import FixReport

    fixes = collect_fixes(path, dry_run=dry_run)
    if output == "json":
        payload = FixReport(target=str(path), dry_run=dry_run, actions=fixes)
        typer.echo(payload.model_dump_json(indent=2))
        return
    console.print(
        f"\n[cyan]{'Previewing fixes for' if dry_run else 'Fixing'}[/] {path} ...\n"
    )
    render_fixes(fixes, dry_run)


@app.command()
def explain(
    target: str = typer.Argument(".", help="Local path to explain"),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich, json, or markdown"
    ),
) -> None:
    """Explain a project in plain English — what it is, what it uses, how it's organized."""
    path = _resolve_dir(target)

    from repomedic.commands.explain import (
        collect_explain,
        render_explain,
        render_explain_markdown,
    )

    data = collect_explain(path)
    if output == "json":
        typer.echo(data.model_dump_json(indent=2))
    elif output in ("markdown", "md"):
        typer.echo(render_explain_markdown(data))
    else:
        render_explain(data, path, console)


@app.command()
def doctor(
    target: str = typer.Argument(".", help="Local path to check environment for"),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich or json"
    ),
) -> None:
    """Check your development environment — interpreters, toolchains, dependencies."""
    path = _resolve_dir(target)

    from repomedic.commands.doctor import collect_doctor, render_doctor

    data = collect_doctor(path)
    if output == "json":
        typer.echo(data.model_dump_json(indent=2))
    else:
        console.print(f"\n[cyan]Checking environment for[/] {path} ...\n")
        render_doctor(data, console)
    raise typer.Exit(0 if data.healthy else 1)


@app.command()
def selfcheck(
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format: rich or json"
    ),
) -> None:
    """Verify the installed package, core pipeline, schemas, and render safety."""
    if output not in {"rich", "json"}:
        err_console.print(
            f"[red]Error:[/] invalid --output '{output}' (choose from: rich, json)"
        )
        raise typer.Exit(2)

    from repomedic.commands.selfcheck import collect_selfcheck, render_selfcheck

    data = collect_selfcheck()
    if output == "json":
        typer.echo(data.model_dump_json(indent=2))
    else:
        render_selfcheck(data, console)
    raise typer.Exit(0 if data.healthy else 1)


@app.command()
def schema(
    kind: str = typer.Option(
        "report",
        "--kind",
        "-k",
        help="Payload kind: report, baseline, doctor, explain, fix, analyzers, selfcheck",
    ),
) -> None:
    """Print the JSON Schema for a repomedic output payload (for validators/contract tests)."""
    import json

    from pydantic import BaseModel

    from repomedic.core.baseline import BaselineFile
    from repomedic.models_commands import (
        AnalyzerList,
        DoctorReport,
        ExplainReport,
        FixReport,
        SelfcheckReport,
    )

    models: dict[str, type[BaseModel]] = {
        "report": ScanReport,
        "baseline": BaselineFile,
        "doctor": DoctorReport,
        "explain": ExplainReport,
        "fix": FixReport,
        "analyzers": AnalyzerList,
        "selfcheck": SelfcheckReport,
    }
    model = models.get(kind)
    if model is None:
        err_console.print(
            f"[red]Error:[/] invalid --kind '{kind}' (choose from: {', '.join(models)})"
        )
        raise typer.Exit(2)
    typer.echo(json.dumps(model.model_json_schema(), indent=2))


@app.command()
def mcp() -> None:
    """Run the MCP server on stdio — exposes RepoMedic tools to agent harnesses."""
    from repomedic.mcp_server import serve

    try:
        serve()
    except RuntimeError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(2) from exc


@app.command()
def agents() -> None:
    """Print the agent integration guide (markdown) — how agents should use this tool."""
    from repomedic.commands.agents import get_agent_guide

    # nl=False: the guide ends with its own newline, and the docs-sync
    # contract is `repomedic agents > docs/AGENTS.md` being byte-equal.
    typer.echo(get_agent_guide(), nl=False)


def _dispatch_cli(args: list[str]) -> int:
    """Run a repomedic CLI invocation in-process, returning its exit code.

    The menu uses this so every action goes through the same argument
    parsing and rendering as a normal terminal invocation.
    """
    try:
        app(args=args, standalone_mode=False)
    except click.exceptions.Exit as exc:
        return exc.exit_code
    except click.ClickException as exc:
        exc.show()
        return 2
    except click.exceptions.Abort:
        return 130
    return 0


@app.command()
def menu() -> None:
    """Interactive launcher — also what bare `repomedic` opens on a terminal."""
    from repomedic.commands.menu import run_menu

    raise typer.Exit(run_menu(_dispatch_cli, console))
