"""Auto-fix command — apply safe, automated fixes to common issues."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from repomedic.utils.process import run

console = Console()

# Default Python .gitignore entries
_GITIGNORE_DEFAULTS = """\
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
dist/
*.egg-info/
*.egg
.eggs/

# Virtual environments
.venv/
venv/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Environment
.env
.env.*

# OS
.DS_Store
Thumbs.db

# Testing
.pytest_cache/
.coverage
htmlcov/
"""


def collect_fixes(target: Path, dry_run: bool = False) -> list[tuple[str, str, str]]:
    """Run (or preview) all auto-fixes. Returns (action, description, status) rows."""
    return [
        _fix_ruff(target, dry_run),
        _fix_gitignore(target, dry_run),
        _fix_env_example(target, dry_run),
    ]


def render_fixes(fixes: list[tuple[str, str, str]], dry_run: bool = False, out: Console | None = None) -> None:
    """Render fix results as a rich table."""
    out = out or console
    title = "Fix Summary (dry run — nothing changed)" if dry_run else "Fix Summary"
    table = Table(title=title, show_header=True, header_style="bold", expand=True)
    table.add_column("Action", min_width=20)
    table.add_column("Description", min_width=30)
    table.add_column("Status", width=12, justify="center")

    for action, desc, status in fixes:
        if status in ("FIXED", "WOULD FIX"):
            style = "green"
        elif status == "SKIPPED":
            style = "yellow"
        else:
            style = "red"
        table.add_row(action, desc, f"[{style}]{status}[/{style}]")

    out.print(table)


def run_fix(target: Path, dry_run: bool = False) -> list[tuple[str, str, str]]:
    """Run all auto-fixes on the target directory, print a summary, return rows."""
    fixes = collect_fixes(target, dry_run)
    render_fixes(fixes, dry_run)
    return fixes


def _fix_ruff(target: Path, dry_run: bool = False) -> tuple[str, str, str]:
    """Run ruff check --fix (or --diff in dry-run mode)."""
    if dry_run:
        result = run(["ruff", "check", "--diff", str(target)], cwd=str(target), timeout=30)
        if result.returncode < 0:
            return ("Ruff auto-fix", "Auto-fix lint issues with ruff", "SKIPPED")
        if result.stdout.strip():
            n_hunks = result.stdout.count("--- ")
            return ("Ruff auto-fix", f"Would apply fixes to {n_hunks} file(s)", "WOULD FIX")
        return ("Ruff auto-fix", "No fixable lint issues found", "SKIPPED")

    result = run(["ruff", "check", "--fix", str(target)], cwd=str(target), timeout=30)
    if result.returncode < 0:
        return ("Ruff auto-fix", "Auto-fix lint issues with ruff", "SKIPPED")

    # Check if ruff made changes
    if "Fixed" in result.stdout or "fixed" in result.stdout:
        return ("Ruff auto-fix", f"Applied ruff fixes: {result.stdout.strip().splitlines()[-1] if result.stdout.strip() else 'done'}", "FIXED")

    if result.returncode == 0:
        return ("Ruff auto-fix", "No fixable lint issues found", "SKIPPED")

    return ("Ruff auto-fix", "Ruff ran but some issues remain (not auto-fixable)", "SKIPPED")


def _fix_gitignore(target: Path, dry_run: bool = False) -> tuple[str, str, str]:
    """Generate .gitignore with Python defaults if missing."""
    gitignore = target / ".gitignore"
    if gitignore.exists():
        return (".gitignore", "Already exists", "SKIPPED")

    if dry_run:
        return (".gitignore", "Would create with Python defaults", "WOULD FIX")

    gitignore.write_text(_GITIGNORE_DEFAULTS, encoding="utf-8")
    return (".gitignore", "Created with Python defaults", "FIXED")


def _fix_env_example(target: Path, dry_run: bool = False) -> tuple[str, str, str]:
    """Create .env.example from .env with values stripped."""
    env_file = target / ".env"
    if not env_file.is_file():
        return (".env.example", "No .env file found", "SKIPPED")

    example_path = target / ".env.example"
    if example_path.exists():
        return (".env.example", "Already exists", "SKIPPED")

    lines = []
    try:
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                lines.append(line)
            elif "=" in stripped:
                key = stripped.split("=", 1)[0]
                lines.append(f"{key}=")
            else:
                lines.append(line)
    except OSError:
        return (".env.example", "Could not read .env file", "ERROR")

    n_keys = len([line for line in lines if "=" in line])
    if dry_run:
        return (".env.example", f"Would create with {n_keys} keys (values stripped)", "WOULD FIX")

    example_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return (".env.example", f"Created with {n_keys} keys (values stripped)", "FIXED")
