"""Doctor command — check development environment health.

Split into collect (pure data) and render (presentation) so the CLI can emit
JSON for agents without any table noise on stdout.
"""

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

# Statuses: OK (present), MISSING (required but absent), OPTIONAL (absent, nice to have)
OK = "OK"
MISSING = "MISSING"
OPTIONAL = "OPTIONAL"

# Optional analysis tools repomedic integrates with, and why they're useful.
_OPTIONAL_TOOLS: list[tuple[str, list[str], str]] = [
    ("semgrep", ["semgrep", "--version"], "pip install semgrep"),
    ("gitleaks", ["gitleaks", "version"], "https://github.com/gitleaks/gitleaks"),
    ("shellcheck", ["shellcheck", "--version"], "apt/brew install shellcheck"),
]


def _check_tool(name: str, cmd: list[str]) -> tuple[str, str, str]:
    """Check if a tool is installed and get its version. Returns (name, version, status)."""
    result = run(cmd, timeout=10)
    if not result.ok:
        return (name, "not found", MISSING)
    version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "installed"
    return (name, version, OK)


def _is_python_project(target: Path) -> bool:
    return (
        (target / "pyproject.toml").is_file()
        or (target / "requirements.txt").is_file()
        or any(target.glob("*.py"))
    )


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
                if not result.ok:
                    findings.append((f"pip: {name}", "not installed", MISSING))
                else:
                    ver_lines = [ln for ln in result.stdout.splitlines() if ln.startswith("Version:")]
                    ver = ver_lines[0].split(":")[1].strip() if ver_lines else "installed"
                    findings.append((f"pip: {name}", ver, OK))
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
                    if not result.ok:
                        findings.append((f"pip: {name}", "not installed", MISSING))
                    else:
                        ver_lines = [ln for ln in result.stdout.splitlines() if ln.startswith("Version:")]
                        ver = ver_lines[0].split(":")[1].strip() if ver_lines else "installed"
                        findings.append((f"pip: {name}", ver, OK))
        except OSError as exc:
            logger.warning("Failed to read requirements.txt: %s", exc)

    return findings


def collect_doctor(target: Path) -> dict:
    """Gather environment health data without printing anything."""
    checks: list[tuple[str, str, str]] = []
    fix_commands: list[str] = []

    # Core tools
    checks.append(_check_tool("Python", ["python3", "--version"]))
    checks.append(_check_tool("git", ["git", "--version"]))
    checks.append(_check_tool("pip", ["pip", "--version"]))

    is_python = _is_python_project(target)

    # Python-project checks: venv, ruff, declared dependencies
    if is_python:
        venv_dirs = [target / d for d in (".venv", "venv", "env")]
        active_venv = next((d for d in venv_dirs if d.is_dir()), None)
        if active_venv:
            checks.append(("Virtual env", f"found ({active_venv.name}/)", OK))
        else:
            checks.append(("Virtual env", "no venv found", MISSING))
            fix_commands.append("python3 -m venv .venv && source .venv/bin/activate")

        ruff_check = _check_tool("ruff", ["ruff", "--version"])
        checks.append(ruff_check)
        if ruff_check[2] == MISSING:
            fix_commands.append("pip install ruff")

    # Per-language toolchains, driven by project markers
    if (target / "package.json").is_file():
        node_check = _check_tool("node", ["node", "--version"])
        npm_check = _check_tool("npm", ["npm", "--version"])
        checks.append(node_check)
        checks.append(npm_check)
        if node_check[2] == MISSING:
            fix_commands.append("Install Node.js from https://nodejs.org")

    if (target / "go.mod").is_file():
        go_check = _check_tool("go", ["go", "version"])
        checks.append(go_check)
        if go_check[2] == MISSING:
            fix_commands.append("Install Go from https://go.dev/dl")

    if (target / "Cargo.toml").is_file():
        cargo_check = _check_tool("cargo", ["cargo", "--version"])
        checks.append(cargo_check)
        if cargo_check[2] == MISSING:
            fix_commands.append("Install Rust via https://rustup.rs")

    if (target / "Gemfile").is_file():
        checks.append(_check_tool("ruby", ["ruby", "--version"]))

    if (target / "composer.json").is_file():
        checks.append(_check_tool("php", ["php", "--version"]))

    # Optional analysis tools — absent is a soft status, not a failure
    for name, cmd, install_hint in _OPTIONAL_TOOLS:
        tool_name, version, status = _check_tool(name, cmd)
        if status == MISSING:
            checks.append((tool_name, f"not installed ({install_hint})", OPTIONAL))
        else:
            checks.append((tool_name, version, OK))

    # Project dependencies
    dep_checks = _check_dependencies_installed(target)
    checks.extend(dep_checks)
    missing_deps = [c[0].replace("pip: ", "") for c in dep_checks if c[2] == MISSING]
    if missing_deps:
        fix_commands.append(f"pip install {' '.join(missing_deps)}")

    return {
        "target": str(target),
        "checks": checks,
        "fix_commands": fix_commands,
        "healthy": not any(status == MISSING for _, _, status in checks),
    }


def render_doctor(data: dict, out: Console | None = None) -> None:
    """Render collected doctor data as rich tables."""
    out = out or console
    table = Table(title="Environment Health Check", show_header=True, header_style="bold", expand=True)
    table.add_column("Check", min_width=20)
    table.add_column("Version / Info", min_width=25)
    table.add_column("Status", width=10, justify="center")

    for name, info, status in data["checks"]:
        if status == OK:
            style, icon = "green", "✓"
        elif status == OPTIONAL:
            style, icon = "dim", "○"
        else:
            style, icon = "red", "✗"
        table.add_row(name, info, f"[{style}]{icon} {status}[/{style}]")

    out.print(table)

    if data["fix_commands"]:
        out.print()
        lines = [f"  [bold]{i}.[/] [cyan]{cmd}[/]" for i, cmd in enumerate(data["fix_commands"], 1)]
        out.print(Panel("\n".join(lines), title="Fix Commands", border_style="yellow"))
    else:
        out.print()
        out.print("[bold green]Everything looks good![/]")
