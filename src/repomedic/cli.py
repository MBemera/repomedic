"""Typer CLI for repomedic.

Agent-first design rules:
- Never prompt unless --interactive is passed. Defaults just work.
- Machine outputs (json/markdown-to-stdout) keep stdout pure; progress and
  status go to stderr.
- Exit codes are meaningful: 0 clean, 1 findings at/above --fail-on, 2 usage.
"""

from __future__ import annotations

import json as json_lib
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional  # noqa: UP035

import typer
from rich.console import Console
from rich.panel import Panel
from typer.core import TyperGroup

from repomedic.analyzers import get_all_analyzers
from repomedic.core.config import VALID_FAIL_ON, VALID_SEVERITIES, load_config
from repomedic.core.scanner import Scanner
from repomedic.models import ScanReport
from repomedic.output.json_output import print_json
from repomedic.output.markdown_output import generate_fix_report, render_fix_report
from repomedic.output.rich_output import print_rich
from repomedic.utils.process import run as run_proc
from repomedic.utils.vcs import changed_files


class DefaultScanGroup(TyperGroup):
    """Click group that routes bare paths/flags to the `scan` command.

    Makes `repomedic`, `repomedic .`, and `repomedic --output json src/`
    all behave as `repomedic scan ...` while keeping normal subcommand
    dispatch (`repomedic sniff .`) intact.
    """

    default_command = "scan"

    def parse_args(self, ctx, args: list[str]) -> list[str]:  # noqa: ANN001 — click Context (vendored in typer)
        has_command = any(not a.startswith("-") and a in self.commands for a in args)
        if not has_command:
            non_options = [a for a in args if not a.startswith("-")]
            wants_group_help = not non_options and any(a in ("--help", "-h") for a in args)
            if not wants_group_help:
                args = [self.default_command, *args]
        return super().parse_args(ctx, args)


app = typer.Typer(
    name="repomedic",
    cls=DefaultScanGroup,
    help=(
        "Agent-first repo bug sniffer — diagnose issues in folders and repos, "
        "hand the fixes to a coding agent. Run `repomedic agents` for the agent guide. "
        "Bare `repomedic [PATH]` is shorthand for `repomedic scan [PATH]`."
    ),
    no_args_is_help=False,
)

console = Console()
err_console = Console(stderr=True)

GITHUB_RE = re.compile(
    r"^(https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?|git@github\.com:[\w\-\.]+/[\w\-\.]+(?:\.git)?)$"
)

STDOUT_SENTINEL = "-"


def _clone_repo(url: str) -> Path:
    """Clone a GitHub repo into a temp directory and return the path."""
    clone_dir = Path(tempfile.mkdtemp(prefix="repomedic_"))
    err_console.print(f"[cyan]Cloning[/] {url} ...")
    result = run_proc(["git", "clone", "--depth", "1", url, str(clone_dir)], timeout=120)
    if not result.ok:
        err_console.print(f"[red]Clone failed:[/] {result.stderr.strip()}")
        raise typer.Exit(2)
    err_console.print(f"[green]Cloned to[/] {clone_dir}")
    return clone_dir


def _resolve_target(target: str) -> tuple[Path, bool]:
    """Resolve target to a directory path. Returns (path, is_temp)."""
    if GITHUB_RE.match(target):
        return _clone_repo(target), True

    path = Path(target).resolve()
    if not path.is_dir():
        err_console.print(f"[red]Error:[/] {target} is not a directory or valid GitHub URL")
        raise typer.Exit(2)
    return path, False


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

    raw = console.input("[bold]Enter numbers separated by spaces[/] (default: 0 = all): ").strip()

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


def _validate_choice(value: str | None, valid: set[str], flag: str) -> None:
    if value is not None and value not in valid:
        err_console.print(f"[red]Error:[/] invalid {flag} '{value}' (choose from: {', '.join(sorted(valid))})")
        raise typer.Exit(2)


def _exit_code_for(report: ScanReport, fail_on: str) -> int:
    """Map summary counts to an exit code according to the fail-on policy."""
    s = report.summary
    if fail_on == "error":
        return 1 if s.errors else 0
    if fail_on == "warning":
        return 1 if s.errors or s.warnings else 0
    if fail_on == "any":
        return 1 if s.total_findings else 0
    return 0  # never


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
) -> None:
    """Shared scan pipeline behind the default command and `sniff`."""
    _validate_choice(min_severity, VALID_SEVERITIES, "--min-severity")
    _validate_choice(fail_on, VALID_FAIL_ON, "--fail-on")
    if output not in {"rich", "json", "markdown", "md"}:
        err_console.print(f"[red]Error:[/] invalid --output '{output}' (choose from: rich, json, markdown)")
        raise typer.Exit(2)

    resolved, is_temp = _resolve_target(target)
    progress = console if output == "rich" else err_console

    try:
        # Per-repo config supplies defaults; CLI flags win.
        cfg = load_config(resolved)
        min_severity = min_severity or cfg.min_severity
        max_findings = max_findings if max_findings is not None else cfg.max_findings
        fail_on = fail_on or cfg.fail_on or "never"

        # Which analyzers to run
        analyzer_list: list[str] | None
        if analyzers:
            analyzer_list = [a.strip() for a in analyzers.split(",")]
            known = {a.name for a in get_all_analyzers()}
            unknown = [a for a in analyzer_list if a.lower() not in known]
            if unknown:
                err_console.print(
                    f"[red]Error:[/] unknown analyzer(s): {', '.join(unknown)}. "
                    f"Run `repomedic list-analyzers`."
                )
                raise typer.Exit(2)
        elif interactive:
            analyzer_list = _pick_analyzers()
        else:
            analyzer_list = cfg.analyzers

        # Changed-files scoping
        only_files: set[str] | None = None
        if changed or since:
            only_files = changed_files(resolved, since=since)
            if only_files is None:
                err_console.print("[red]Error:[/] --changed/--since requires a git repository")
                raise typer.Exit(2)

        label = "all applicable analyzers" if analyzer_list is None else ", ".join(analyzer_list)
        progress.print(f"[cyan]Scanning[/] {resolved} with [bold]{label}[/] ...")

        report = Scanner().scan(
            str(resolved),
            analyzer_names=analyzer_list,
            min_severity=min_severity,
            extra_ignore_dirs=set(cfg.exclude) or None,
            skip_tests=not cfg.include_tests,
            only_files=only_files,
            max_findings=max_findings,
        )

        if report.languages:
            lang_str = ", ".join(f"{name} ({count})" for name, count in report.languages.items())
            progress.print(f"[bold]Languages:[/] {lang_str}")

        # Emit
        if output == "json":
            typer.echo(print_json(report))
        elif output in ("markdown", "md"):
            if report_file == STDOUT_SENTINEL:
                typer.echo(render_fix_report(report, include_snippets=snippets))
            else:
                if report_file:
                    report_path = Path(report_file)
                elif is_temp:
                    report_path = Path.cwd() / "repomedic-fixes.md"
                else:
                    report_path = None
                result_path = generate_fix_report(report, report_path, include_snippets=snippets)
                err_console.print(f"[bold green]✓[/] Fix report written to [cyan]{result_path}[/]")
                err_console.print("  Feed this file to your coding agent for minimal-context fixes.")
        else:
            print_rich(report, console)
            if report.findings:
                console.print()
                console.print(
                    "[dim]Tip: `repomedic sniff .` prints an agent-ready fix report; "
                    "`--output markdown` writes it to a file.[/dim]"
                )

        raise typer.Exit(_exit_code_for(report, fail_on))
    finally:
        if is_temp:
            shutil.rmtree(resolved, ignore_errors=True)


@app.command()
def scan(
    target: str = typer.Argument(".", help="Local path or GitHub URL to scan"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich, json, or markdown"),
    all_analyzers: bool = typer.Option(False, "--all", "-A", help="Run all analyzers (the default; kept for compatibility)"),
    analyzers: Optional[str] = typer.Option(None, "--analyzers", "-a", help="Comma-separated analyzer names"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Pick analyzers interactively"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", "-s", help="Minimum severity: error, warning, info"),
    report_file: Optional[str] = typer.Option(None, "--report-file", "-r", help="Markdown report path ('-' = stdout; default: <target>/repomedic-fixes.md)"),
    changed: bool = typer.Option(False, "--changed", help="Only report findings in git-changed files"),
    since: Optional[str] = typer.Option(None, "--since", help="Only report findings in files changed since this git ref"),
    max_findings: Optional[int] = typer.Option(None, "--max-findings", help="Keep only the N most severe findings (0 = unlimited)"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 when findings at/above: error, warning, any, never (default: never)"),
    snippets: bool = typer.Option(True, "--snippets/--no-snippets", help="Include code snippets in markdown reports"),
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
    )


@app.command()
def sniff(
    target: str = typer.Argument(".", help="Local path or GitHub URL to scan"),
    analyzers: Optional[str] = typer.Option(None, "--analyzers", "-a", help="Comma-separated analyzer names"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", "-s", help="Minimum severity: error, warning, info"),
    changed: bool = typer.Option(False, "--changed", help="Only report findings in git-changed files"),
    since: Optional[str] = typer.Option(None, "--since", help="Only report findings in files changed since this git ref"),
    max_findings: Optional[int] = typer.Option(None, "--max-findings", help="Keep only the N most severe findings (default 50; 0 = unlimited)"),
    fail_on: Optional[str] = typer.Option("error", "--fail-on", help="Exit 1 when findings at/above: error, warning, any, never"),
    report_file: Optional[str] = typer.Option(STDOUT_SENTINEL, "--report-file", "-r", help="Markdown report path (default '-' = stdout)"),
    snippets: bool = typer.Option(True, "--snippets/--no-snippets", help="Include code snippets"),
) -> None:
    """Bug-sniff a repo for agents: markdown fix report on stdout, exit 1 on errors."""
    _execute_scan(
        target,
        output="markdown",
        analyzers=analyzers,
        interactive=False,
        min_severity=min_severity,
        report_file=report_file,
        changed=changed,
        since=since,
        max_findings=max_findings if max_findings is not None else 50,
        fail_on=fail_on,
        snippets=snippets,
    )


@app.command()
def run(
    script: str = typer.Argument(..., help="Script to run (py, js, sh, rb, php, pl, lua)"),
    args: Optional[list[str]] = typer.Argument(None, help="Arguments passed to the script"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json, rich, or markdown"),
) -> None:
    """Run a script with the matching interpreter and analyze its failure."""
    from repomedic.analyzers.runtime import RuntimeAnalyzer

    script_path = Path(script).resolve()
    if not script_path.is_file():
        err_console.print(f"[red]Error:[/] {script} is not a file")
        raise typer.Exit(2)

    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script_path), cwd=str(script_path.parent), args=args or [])

    report = ScanReport(target=str(script_path), results=[result])
    report.build_summary()

    if output == "rich":
        print_rich(report, console)
    elif output in ("markdown", "md"):
        typer.echo(render_fix_report(report))
    else:
        typer.echo(print_json(report))

    # `result.error` is set (with zero findings) when the script could not be run
    # at all — an unsupported extension or a missing interpreter. That is still a
    # failure, so print it to stderr (stdout stays clean for JSON consumers) and
    # make sure the exit code reflects it, not just error-severity findings.
    if result.error:
        err_console.print(f"[red]Could not run script:[/] {result.error}")

    # Exit 1 when the script failed to run OR ran and produced error findings.
    raise typer.Exit(1 if report.summary.errors or result.error else 0)


@app.command("list-analyzers")
def list_analyzers(
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich or json"),
) -> None:
    """List all available analyzers."""
    analyzers = get_all_analyzers()
    if output == "json":
        typer.echo(json_lib.dumps(
            [{"name": a.name, "description": a.description} for a in analyzers],
            indent=2,
        ))
        return
    for a in analyzers:
        console.print(f"  [bold]{a.name}[/] — {a.description}")


@app.command()
def fix(
    target: str = typer.Argument(".", help="Local path to fix"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview fixes without changing anything"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich or json"),
) -> None:
    """Auto-fix common issues (ruff, .gitignore, .env.example)."""
    path = _resolve_dir(target)

    from repomedic.commands.fix import collect_fixes, render_fixes

    fixes = collect_fixes(path, dry_run=dry_run)
    if output == "json":
        typer.echo(json_lib.dumps(
            [{"action": a, "description": d, "status": s} for a, d, s in fixes],
            indent=2,
        ))
        return
    console.print(f"\n[cyan]{'Previewing fixes for' if dry_run else 'Fixing'}[/] {path} ...\n")
    render_fixes(fixes, dry_run)


@app.command()
def explain(
    target: str = typer.Argument(".", help="Local path to explain"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich, json, or markdown"),
) -> None:
    """Explain a project in plain English — what it is, what it uses, how it's organized."""
    path = _resolve_dir(target)

    from repomedic.commands.explain import collect_explain, render_explain, render_explain_markdown

    data = collect_explain(path)
    if output == "json":
        typer.echo(json_lib.dumps(data, indent=2))
    elif output in ("markdown", "md"):
        typer.echo(render_explain_markdown(data))
    else:
        render_explain(data, path, console)


@app.command()
def doctor(
    target: str = typer.Argument(".", help="Local path to check environment for"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich or json"),
) -> None:
    """Check your development environment — interpreters, toolchains, dependencies."""
    path = _resolve_dir(target)

    from repomedic.commands.doctor import collect_doctor, render_doctor

    data = collect_doctor(path)
    if output == "json":
        typer.echo(json_lib.dumps(data, indent=2))
    else:
        console.print(f"\n[cyan]Checking environment for[/] {path} ...\n")
        render_doctor(data, console)
    raise typer.Exit(0 if data["healthy"] else 1)


@app.command()
def agents() -> None:
    """Print the agent integration guide (markdown) — how agents should use this tool."""
    from repomedic.commands.agents import get_agent_guide

    typer.echo(get_agent_guide())
