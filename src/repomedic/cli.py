"""Typer CLI for repomedic."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional  # noqa: UP035

import typer
from rich.console import Console
from rich.panel import Panel
from repomedic.analyzers import get_all_analyzers
from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.core.scanner import Scanner
from repomedic.output.json_output import print_json
from repomedic.output.markdown_output import generate_fix_report
from repomedic.output.rich_output import print_rich
from repomedic.utils.process import run as run_proc

app = typer.Typer(
    name="repomedic",
    help="AI-agent repo debugging system — diagnose issues in folders and repos.",
    invoke_without_command=True,
)

console = Console()

GITHUB_RE = re.compile(
    r"^(https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?|git@github\.com:[\w\-\.]+/[\w\-\.]+(?:\.git)?)$"
)


def _clone_repo(url: str) -> Path:
    """Clone a GitHub repo into a temp directory and return the path."""
    clone_dir = Path(tempfile.mkdtemp(prefix="repomedic_"))
    console.print(f"[cyan]Cloning[/] {url} ...")
    result = run_proc(["git", "clone", "--depth", "1", url, str(clone_dir)], timeout=120)
    if result.returncode != 0:
        console.print(f"[red]Clone failed:[/] {result.stderr.strip()}")
        raise typer.Exit(1)
    console.print(f"[green]Cloned to[/] {clone_dir}\n")
    return clone_dir


def _resolve_target(target: str) -> tuple[Path, bool]:
    """Resolve target to a directory path. Returns (path, is_temp)."""
    if GITHUB_RE.match(target):
        return _clone_repo(target), True

    path = Path(target).resolve()
    if not path.is_dir():
        console.print(f"[red]Error:[/] {target} is not a directory or valid GitHub URL")
        raise typer.Exit(1)
    return path, False


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


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    target: Optional[str] = typer.Argument(None, help="Local path or GitHub URL to scan"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: json, rich, or markdown"),
    all_analyzers: bool = typer.Option(False, "--all", "-A", help="Run all analyzers without prompting"),
    analyzers: Optional[str] = typer.Option(None, "--analyzers", "-a", help="Comma-separated analyzer names (skip prompt)"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", "-s", help="Minimum severity: error, warning, info"),
    report_file: Optional[str] = typer.Option(None, "--report-file", "-r", help="Output file path for markdown report (default: <target>/repomedic-fixes.md)"),
) -> None:
    """Scan a local folder or GitHub repo for issues."""
    if ctx.invoked_subcommand is not None:
        return

    # If no target given, default to current directory
    if target is None:
        target = "."

    resolved, is_temp = _resolve_target(target)

    # Determine which analyzers to run
    if analyzers:
        analyzer_list = [a.strip() for a in analyzers.split(",")]
    elif all_analyzers:
        analyzer_list = None
    else:
        analyzer_list = _pick_analyzers()

    label = "all analyzers" if analyzer_list is None else ", ".join(analyzer_list)
    console.print(f"\n[cyan]Scanning[/] {resolved} with [bold]{label}[/] ...\n")

    scanner = Scanner()

    # Detect and display languages
    from repomedic.core.context import ScanContext
    ctx_preview = ScanContext(str(resolved))
    langs = ctx_preview.detected_languages
    if langs:
        lang_str = ", ".join(sorted(langs))
        console.print(f"[bold]Languages detected:[/] {lang_str}\n")

    # Scan runs analyzers + doctor + explain automatically
    report = scanner.scan(str(resolved), analyzer_names=analyzer_list, min_severity=min_severity)
    console.print()  # spacer after doctor/explain output

    if output == "json":
        typer.echo(print_json(report))
    elif output == "markdown" or output == "md":
        if report_file:
            report_path = Path(report_file)
        elif is_temp:
            report_path = Path.cwd() / "repomedic-fixes.md"
        else:
            report_path = None
        result_path = generate_fix_report(report, report_path)
        console.print(f"[bold green]✓[/] Fix report written to [cyan]{result_path}[/]")
        console.print("  Feed this file to your coding agent for minimal-context fixes.")
    else:
        print_rich(report, console)
        # Ask to generate a markdown report if there are findings
        if report.findings:
            console.print()
            do_report = typer.confirm("Would you like to generate a Markdown fix report for an AI coding agent?", default=True)
            if do_report:
                if report_file:
                    report_path = Path(report_file)
                elif is_temp:
                    report_path = Path.cwd() / "repomedic-fixes.md"
                else:
                    report_path = None
                result_path = generate_fix_report(report, report_path)
                console.print(f"[bold green]✓[/] Fix report written to [cyan]{result_path}[/]")
                console.print("  Feed this file to your coding agent for minimal-context fixes.")

    # Cleanup temp clone
    if is_temp:
        shutil.rmtree(resolved, ignore_errors=True)


@app.command()
def run(
    script: str = typer.Argument(..., help="Path to the Python script to run"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json or rich"),
) -> None:
    """Run a Python script and analyze its output."""
    script_path = Path(script).resolve()
    if not script_path.is_file():
        console.print(f"[red]Error:[/] {script} is not a file")
        raise typer.Exit(1)

    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script_path), cwd=str(script_path.parent))

    from repomedic.models import ScanReport

    report = ScanReport(target=str(script_path), results=[result])
    report.build_summary()

    if output == "rich":
        print_rich(report, console)
    else:
        typer.echo(print_json(report))


@app.command("list-analyzers")
def list_analyzers() -> None:
    """List all available analyzers."""
    analyzers = get_all_analyzers()
    for a in analyzers:
        console.print(f"  [bold]{a.name}[/] — {a.description}")


@app.command()
def fix(
    target: str = typer.Argument(".", help="Local path to fix"),
) -> None:
    """Auto-fix common issues (ruff, .gitignore, .env.example)."""
    path = Path(target).resolve()
    if not path.is_dir():
        console.print(f"[red]Error:[/] {target} is not a directory")
        raise typer.Exit(1)

    console.print(f"\n[cyan]Fixing[/] {path} ...\n")
    from repomedic.commands.fix import run_fix

    run_fix(path)


@app.command()
def explain(
    target: str = typer.Argument(".", help="Local path to explain"),
) -> None:
    """Explain a project in plain English — what it is, what it uses, how it's organized."""
    path = Path(target).resolve()
    if not path.is_dir():
        console.print(f"[red]Error:[/] {target} is not a directory")
        raise typer.Exit(1)

    from repomedic.commands.explain import run_explain

    run_explain(path)


@app.command()
def doctor(
    target: str = typer.Argument(".", help="Local path to check environment for"),
) -> None:
    """Check your development environment — Python, git, pip, dependencies."""
    path = Path(target).resolve()
    if not path.is_dir():
        console.print(f"[red]Error:[/] {target} is not a directory")
        raise typer.Exit(1)

    console.print(f"\n[cyan]Checking environment for[/] {path} ...\n")
    from repomedic.commands.doctor import run_doctor

    run_doctor(path)
