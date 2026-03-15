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


def run_fix(target: Path) -> None:
    """Run all auto-fixes on the target directory."""
    fixes: list[tuple[str, str, str]] = []  # (action, description, status)

    # 1. Ruff auto-fix
    fixes.append(_fix_ruff(target))

    # 2. Generate .gitignore if missing
    fixes.append(_fix_gitignore(target))

    # 3. Create .env.example from .env
    fixes.append(_fix_env_example(target))

    # Summary table
    table = Table(title="Fix Summary", show_header=True, header_style="bold", expand=True)
    table.add_column("Action", min_width=20)
    table.add_column("Description", min_width=30)
    table.add_column("Status", width=12, justify="center")

    for action, desc, status in fixes:
        style = "green" if status == "FIXED" else ("yellow" if status == "SKIPPED" else "red")
        table.add_row(action, desc, f"[{style}]{status}[/{style}]")

    console.print(table)


def _fix_ruff(target: Path) -> tuple[str, str, str]:
    """Run ruff check --fix."""
    result = run(["ruff", "check", "--fix", str(target)], cwd=str(target), timeout=30)
    if result.returncode < 0:
        return ("Ruff auto-fix", "Auto-fix lint issues with ruff", "SKIPPED")

    # Check if ruff made changes
    if "Fixed" in result.stdout or "fixed" in result.stdout:
        return ("Ruff auto-fix", f"Applied ruff fixes: {result.stdout.strip().splitlines()[-1] if result.stdout.strip() else 'done'}", "FIXED")

    if result.returncode == 0:
        return ("Ruff auto-fix", "No fixable lint issues found", "SKIPPED")

    return ("Ruff auto-fix", "Ruff ran but some issues remain (not auto-fixable)", "SKIPPED")


def _fix_gitignore(target: Path) -> tuple[str, str, str]:
    """Generate .gitignore with Python defaults if missing."""
    gitignore = target / ".gitignore"
    if gitignore.exists():
        return (".gitignore", "Already exists", "SKIPPED")

    gitignore.write_text(_GITIGNORE_DEFAULTS, encoding="utf-8")
    return (".gitignore", "Created with Python defaults", "FIXED")


def _fix_env_example(target: Path) -> tuple[str, str, str]:
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

    example_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return (".env.example", f"Created with {len([line for line in lines if '=' in line])} keys (values stripped)", "FIXED")
