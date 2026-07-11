"""Interactive startup menu — what bare `repomedic` opens on a terminal.

Humans get a launcher; agents never see it. The menu is routed only when
no CLI arguments were given AND stdin/stdout are TTYs, so piped, scripted,
and harness invocations keep the agent-first scan default unchanged.

The "Fix with coding agent" action hands the codebase to a coding agent
with minimal token spend: the scan report is written to a file and the
agent is launched with a short constant prompt pointing at it, instead of
inlining the whole report into the agent's context.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.panel import Panel

Dispatch = Callable[[list[str]], int]
Ask = Callable[[str], str]

REPORT_FILENAME = "repomedic-fixes.md"

DEFAULT_AGENT_COMMAND = "claude"

# Deliberately tiny: the findings live in the report file, which the agent
# reads with its own tools. Keeping the prompt constant means handoff cost
# does not grow with the number of findings.
AGENT_PROMPT = (
    f"Read {REPORT_FILENAME} in this directory and fix the findings, errors "
    "first. Reference findings by their RM- fingerprint IDs, and when done "
    "run the commands the report lists under 'Verify after fixing'."
)

MENU_CHOICES = [
    ("1", "Scan this folder", "rich TUI report"),
    ("2", "Scan a path or GitHub URL", "URLs scan with --no-exec"),
    ("3", "Agent fix report", "markdown for a coding agent"),
    ("4", "Fix with coding agent", "scan, then hand off to your agent"),
    ("5", "Preview auto-fixes", "dry run, changes nothing"),
    ("6", "Debug a Python script", "capture crash frames and locals"),
    ("7", "Environment doctor", "interpreters, toolchains, dependencies"),
    ("8", "Selfcheck", "verify this installation"),
    ("q", "Quit", ""),
]


def stdio_is_interactive() -> bool:
    """True when a human is at the terminal (menu allowed)."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def agent_command() -> list[str]:
    """The coding-agent launch command, as argv.

    Read from the REPOMEDIC_AGENT environment variable (the user's own
    environment — never from the scanned repo's config, which must not be
    able to choose what binary gets executed).
    """
    return shlex.split(os.environ.get("REPOMEDIC_AGENT", "") or DEFAULT_AGENT_COMMAND)


def _render_menu(console: Console) -> None:
    lines = []
    for key, label, hint in MENU_CHOICES:
        hint_part = f"  [dim]{hint}[/]" if hint else ""
        lines.append(f"  [bold green]{key}[/]  {label:<26}{hint_part}")
    console.print(Panel("\n".join(lines), title="RepoMedic — what do you want to do?", border_style="cyan"))


def _ask_directory(ask: Ask, prompt: str) -> str:
    raw = ask(f"[bold]{prompt}[/] (default: current directory): ").strip()
    return raw or "."


def run_agent_handoff(dispatch: Dispatch, console: Console, ask: Ask) -> int:
    """Scan a local directory, then launch the coding agent on the report.

    Token-lean by design: findings go to a report file; the agent gets a
    short constant prompt pointing at it. Launch always requires explicit
    confirmation because the agent will be editing the codebase.
    """
    target = _ask_directory(ask, "Directory to fix")
    target_dir = Path(target).resolve()
    if not target_dir.is_dir():
        console.print(f"[red]Error:[/] {target} is not a local directory (handoff needs one)")
        return 2

    report_path = target_dir / REPORT_FILENAME
    exit_code = dispatch(
        [
            "scan", str(target_dir),
            "--output", "markdown",
            "--report-file", str(report_path),
            "--fail-on", "warning",
        ]
    )
    if exit_code == 0:
        console.print("[green]No errors or warnings — nothing to hand off.[/]")
        return 0
    if exit_code != 1:
        return exit_code

    command = [*agent_command(), AGENT_PROMPT]
    console.print(f"\nReport written to [cyan]{report_path}[/]")
    console.print(f"About to run [bold]{shlex.join(command)}[/]")
    console.print(f"in [cyan]{target_dir}[/] — the agent will edit this codebase.")
    if ask("[bold]Launch agent?[/] \\[y/N]: ").strip().lower() != "y":
        console.print("[dim]Cancelled. The report file is still there for manual use.[/]")
        return 0

    try:
        # The user's own interactive agent session: it inherits the
        # terminal and environment on purpose (unlike scan subprocesses,
        # which run isolated). No shell is involved.
        completed = subprocess.run(command, cwd=target_dir)
    except FileNotFoundError:
        console.print(
            f"[red]Error:[/] agent command not found: {shlex.join(agent_command())}. "
            "Install it or set REPOMEDIC_AGENT to your agent CLI."
        )
        return 2
    return completed.returncode


def _action_for(choice: str, dispatch: Dispatch, console: Console, ask: Ask) -> int | None:
    """Run one menu choice; None means the choice was not recognized."""
    if choice == "1":
        return dispatch(["scan", "."])
    if choice == "2":
        target = ask("[bold]Path or GitHub URL[/]: ").strip()
        return dispatch(["scan", target]) if target else 2
    if choice == "3":
        return dispatch(["sniff", _ask_directory(ask, "Directory to report on")])
    if choice == "4":
        return run_agent_handoff(dispatch, console, ask)
    if choice == "5":
        return dispatch(["fix", _ask_directory(ask, "Directory to preview fixes for"), "--dry-run"])
    if choice == "6":
        script = ask("[bold]Python script to debug[/]: ").strip()
        return dispatch(["debug", script, "--output", "rich"]) if script else 2
    if choice == "7":
        return dispatch(["doctor", "."])
    if choice == "8":
        return dispatch(["selfcheck"])
    return None


def run_menu(dispatch: Dispatch, console: Console, ask: Ask | None = None) -> int:
    """Show the launcher until the user quits. Returns the last exit code."""
    ask = ask or console.input
    last_exit = 0
    while True:
        _render_menu(console)
        try:
            choice = ask("[bold]Choice[/]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return last_exit
        if choice == "q":
            return last_exit
        try:
            result = _action_for(choice, dispatch, console, ask)
        except (EOFError, KeyboardInterrupt):
            console.print()
            continue
        if result is None:
            console.print(f"[yellow]Unknown choice:[/] {choice!r}")
            continue
        last_exit = result
        status = "[green]ok[/]" if result == 0 else f"[yellow]exit {result}[/]"
        console.print(f"\n[dim]Done ({status}[dim]). Back to the menu — q to quit.[/]\n")
