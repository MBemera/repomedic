"""Doctor command — check development environment health."""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from repomedic.analyzers.dependencies import parse_dep_name
from repomedic.utils.process import run

logger = logging.getLogger("repomedic")
console = Console()


def _check_tool(name: str, cmd: list[str]) -> tuple[str, str, str]:
    """Check if a tool is installed and get its version. Returns (name, version, status)."""
    result = run(cmd, timeout=10)
    if result.returncode < 0 or result.returncode != 0:
        return (name, "not found", "MISSING")
    version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "installed"
    return (name, version, "OK")


def _check_dependencies_installed(target: Path) -> list[tuple[str, str, str]]:
    """Check if project dependencies are installed."""
    findings = []

    # Check pyproject.toml dependencies
    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            deps = data.get("project", {}).get("dependencies", [])
            for dep in deps:
                name = parse_dep_name(dep)
                result = run(["pip", "show", name], timeout=10)
                if result.returncode != 0:
                    findings.append((f"pip: {name}", "not installed", "MISSING"))
                else:
                    ver_lines = [ln for ln in result.stdout.splitlines() if ln.startswith("Version:")]
                    ver = ver_lines[0].split(":")[1].strip() if ver_lines else "installed"
                    findings.append((f"pip: {name}", ver, "OK"))
        except Exception as exc:
            logger.warning("Failed to check pyproject.toml deps: %s", exc)

    # Check requirements.txt
    req = target / "requirements.txt"
    if req.is_file() and not pyproject.is_file():
        try:
            for raw_line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                raw_line = raw_line.strip()
                if raw_line and not raw_line.startswith("#") and not raw_line.startswith("-"):
                    name = parse_dep_name(raw_line)
                    result = run(["pip", "show", name], timeout=10)
                    if result.returncode != 0:
                        findings.append((f"pip: {name}", "not installed", "MISSING"))
                    else:
                        ver_lines = [ln for ln in result.stdout.splitlines() if ln.startswith("Version:")]
                        ver = ver_lines[0].split(":")[1].strip() if ver_lines else "installed"
                        findings.append((f"pip: {name}", ver, "OK"))
        except OSError as exc:
            logger.warning("Failed to read requirements.txt: %s", exc)

    return findings


def run_doctor(target: Path) -> dict:
    """Check development environment health. Returns structured results."""
    checks: list[tuple[str, str, str]] = []
    fix_commands: list[str] = []

    # Core tools
    checks.append(_check_tool("Python", ["python3", "--version"]))
    checks.append(_check_tool("git", ["git", "--version"]))
    checks.append(_check_tool("pip", ["pip", "--version"]))

    # Check venv in target project
    venv_dirs = [target / d for d in (".venv", "venv", "env")]
    active_venv = next((d for d in venv_dirs if d.is_dir()), None)
    if active_venv:
        checks.append(("Virtual env", f"found ({active_venv.name}/)", "OK"))
    else:
        checks.append(("Virtual env", "no venv found", "MISSING"))
        fix_commands.append("python3 -m venv .venv && source .venv/bin/activate")

    # Ruff
    ruff_check = _check_tool("ruff", ["ruff", "--version"])
    checks.append(ruff_check)
    if ruff_check[2] == "MISSING":
        fix_commands.append("pip install ruff")

    # Node/npm if package.json exists
    if (target / "package.json").is_file():
        node_check = _check_tool("node", ["node", "--version"])
        npm_check = _check_tool("npm", ["npm", "--version"])
        checks.append(node_check)
        checks.append(npm_check)
        if node_check[2] == "MISSING":
            fix_commands.append("Install Node.js from https://nodejs.org")

    # Project dependencies
    dep_checks = _check_dependencies_installed(target)
    checks.extend(dep_checks)
    missing_deps = [c[0].replace("pip: ", "") for c in dep_checks if c[2] == "MISSING"]
    if missing_deps:
        fix_commands.append(f"pip install {' '.join(missing_deps)}")

    # Display table
    table = Table(title="Environment Health Check", show_header=True, header_style="bold", expand=True)
    table.add_column("Check", min_width=20)
    table.add_column("Version / Info", min_width=25)
    table.add_column("Status", width=10, justify="center")

    for name, info, status in checks:
        style = "green" if status == "OK" else "red"
        icon = "✓" if status == "OK" else "✗"
        table.add_row(name, info, f"[{style}]{icon} {status}[/{style}]")

    console.print(table)

    # Fix commands
    if fix_commands:
        console.print()
        lines = [f"  [bold]{i}.[/] [cyan]{cmd}[/]" for i, cmd in enumerate(fix_commands, 1)]
        console.print(Panel("\n".join(lines), title="Fix Commands", border_style="yellow"))
    else:
        console.print()
        console.print("[bold green]Everything looks good![/]")

    return {
        "checks": checks,
        "fix_commands": fix_commands,
    }
