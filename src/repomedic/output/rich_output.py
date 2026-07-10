"""Rich output formatter — vibe-coder friendly report with health score."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from repomedic.models import Finding, ScanReport, Severity

# Finding text (title/suggestion/paths) echoes repo content, so it is always
# escaped before printing — repo-controlled "[red]..."-style markup must
# style nothing. Our own labels keep their colors.

# Map technical severity to friendly labels
_FRIENDLY_LABELS = {
    Severity.error: ("BROKEN", "red"),
    Severity.warning: ("WARNING", "yellow"),
    Severity.info: ("TIP", "blue"),
}

_GRADE_COLORS = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "bold red",
}


def _score_badge(score: int, grade: str) -> str:
    """Build the health score header text."""
    color = _GRADE_COLORS.get(grade, "white")
    bar_filled = score // 5  # 0-20 blocks
    bar_empty = 20 - bar_filled
    bar = f"[green]{'█' * bar_filled}[/][dim]{'░' * bar_empty}[/]"
    return (
        f"[{color}]  ★  Health Score: {score}/100  (Grade: {grade})  ★  [/{color}]\n"
        f"      {bar}  {score}%"
    )


def _group_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Group findings into Fix Now / Should Fix / Nice to Know."""
    fix_now = [f for f in findings if f.severity == Severity.error]
    should_fix = [f for f in findings if f.severity == Severity.warning]
    nice_to_know = [f for f in findings if f.severity == Severity.info]
    return fix_now, should_fix, nice_to_know


def _findings_table(findings: list[Finding], section_label: str, style: str) -> Table:
    """Build a table for a group of findings."""
    table = Table(
        title=f"[{style}]{section_label}[/{style}]",
        show_header=True,
        header_style="bold",
        border_style=style,
        title_justify="left",
        expand=True,
    )
    table.add_column("#", width=3, justify="right")
    table.add_column("Code", width=10)
    table.add_column("What's Wrong", min_width=25)
    table.add_column("Where", min_width=15)
    table.add_column("How to Fix", min_width=30, style="dim")

    for i, f in enumerate(findings, 1):
        label, color = _FRIENDLY_LABELS.get(f.severity, ("INFO", "white"))
        loc = f.file_path or ""
        if f.line:
            loc += f":{f.line}"
        table.add_row(
            str(i),
            f"[{color}]{escape(f.code)}[/{color}]",
            escape(f.title),
            escape(loc),
            escape(f.suggestion[:100] + ("..." if len(f.suggestion) > 100 else "")),
        )
    return table


def _next_steps(findings: list[Finding]) -> Panel:
    """Build a numbered Next Steps panel from unique suggestions."""
    seen: set[str] = set()
    steps: list[str] = []
    # Prioritize errors, then warnings
    for f in sorted(findings, key=lambda x: (x.severity != Severity.error, x.severity != Severity.warning)):
        if f.suggestion and f.suggestion not in seen:
            seen.add(f.suggestion)
            steps.append(f.suggestion)
        if len(steps) >= 7:
            break

    if not steps:
        return Panel("[green]Nothing to do — your project looks great![/]", title="Next Steps", border_style="green")

    lines = []
    for i, step in enumerate(steps, 1):
        lines.append(f"  [bold]{i}.[/] {escape(step)}")

    return Panel("\n".join(lines), title="📋 Next Steps", border_style="cyan")


def print_rich(report: ScanReport, console: Console | None = None) -> None:
    """Print a vibe-coder friendly report to the console."""
    console = console or Console()
    s = report.summary

    # Health Score badge
    badge = _score_badge(s.health_score, s.health_grade)
    console.print(Panel(
        badge + f"\n\n[bold]Target:[/] {escape(report.target)}\n"
        f"[bold]Scanned:[/] {s.analyzers_run} analyzers run, {s.analyzers_failed} failed",
        title="[bold]repomedic[/]",
        border_style="cyan",
    ))

    if not report.findings:
        # "No findings" only means "healthy" if every analyzer actually ran.
        # If one failed (e.g. `repomedic run` on an unsupported script type),
        # say so instead of claiming success.
        if s.analyzers_failed:
            console.print(
                f"\n[yellow]⚠ No findings, but {s.analyzers_failed} analyzer(s) "
                "could not run — results may be incomplete.[/]\n"
            )
        else:
            console.print("\n[bold green]✓ No issues found — your project is healthy![/]\n")
        return

    # Group findings
    fix_now, should_fix, nice_to_know = _group_findings(report.findings)

    if fix_now:
        console.print()
        console.print(_findings_table(fix_now, f"🔴 Fix Now — {len(fix_now)} broken", "red"))

    if should_fix:
        console.print()
        console.print(_findings_table(should_fix, f"🟡 Should Fix — {len(should_fix)} warnings", "yellow"))

    if nice_to_know:
        console.print()
        console.print(_findings_table(nice_to_know, f"🔵 Nice to Know — {len(nice_to_know)} tips", "blue"))

    # Next Steps
    console.print()
    console.print(_next_steps(report.findings))
