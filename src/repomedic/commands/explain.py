"""Explain command — describe a project in plain English (or agent markdown)."""

from __future__ import annotations

import ast
import logging
import tomllib
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from repomedic.core.languages import detect_languages
from repomedic.utils.fs import discover_files

logger = logging.getLogger("repomedic")
console = Console()

# Known dependency descriptions
_DEP_DESCRIPTIONS: dict[str, str] = {
    "flask": "web framework (lightweight)",
    "django": "web framework (full-featured)",
    "fastapi": "modern async web API framework",
    "uvicorn": "ASGI web server for FastAPI/Starlette",
    "gunicorn": "production WSGI web server",
    "requests": "HTTP client for making web requests",
    "httpx": "modern async HTTP client",
    "sqlalchemy": "database ORM and toolkit",
    "pydantic": "data validation using Python types",
    "typer": "CLI framework (like Click but with type hints)",
    "click": "CLI framework",
    "rich": "beautiful terminal output (colors, tables, progress bars)",
    "pytest": "testing framework",
    "numpy": "numerical computing and arrays",
    "pandas": "data analysis and manipulation",
    "scikit-learn": "machine learning library",
    "tensorflow": "deep learning framework",
    "torch": "deep learning framework (PyTorch)",
    "celery": "distributed task queue",
    "redis": "Redis client for caching/queues",
    "boto3": "AWS SDK for Python",
    "pillow": "image processing",
    "matplotlib": "data visualization and plotting",
    "beautifulsoup4": "HTML/XML parsing and web scraping",
    "scrapy": "web scraping framework",
    "alembic": "database migration tool for SQLAlchemy",
    "black": "code formatter",
    "ruff": "fast Python linter",
    "mypy": "static type checker",
    "setuptools": "package building and distribution",
    "hatchling": "modern Python build backend",
    "streamlit": "data app framework",
    "gradio": "ML demo UI builder",
    "openai": "OpenAI API client",
    "langchain": "LLM application framework",
    "anthropic": "Anthropic Claude API client",
    "dotenv": "load environment variables from .env files",
    "python-dotenv": "load environment variables from .env files",
    "jinja2": "HTML templating engine",
    "aiohttp": "async HTTP client/server",
    "websockets": "WebSocket client and server",
    # JavaScript ecosystem
    "react": "UI component library",
    "next": "React web framework (SSR)",
    "vue": "UI framework",
    "express": "Node.js web framework",
    "axios": "HTTP client",
    "lodash": "utility functions",
    "jest": "testing framework",
    "vitest": "testing framework (Vite)",
    "webpack": "module bundler",
    "vite": "dev server and bundler",
    "eslint": "JavaScript linter",
    "prettier": "code formatter",
    "typescript": "typed JavaScript compiler",
}

# Known file/directory descriptions
_KNOWN_PATHS: dict[str, str] = {
    "pyproject.toml": "Project config and dependencies",
    "setup.py": "Legacy package setup script",
    "setup.cfg": "Legacy package configuration",
    "requirements.txt": "Python dependency list",
    "Pipfile": "Pipenv dependency file",
    "package.json": "Node.js project config and dependencies",
    "go.mod": "Go module definition",
    "Cargo.toml": "Rust crate config and dependencies",
    "Gemfile": "Ruby dependency file",
    "composer.json": "PHP dependency file",
    "Dockerfile": "Container build instructions",
    "docker-compose.yml": "Multi-container Docker setup",
    "docker-compose.yaml": "Multi-container Docker setup",
    ".env": "Environment variables (secrets)",
    ".env.example": "Environment variable template",
    ".gitignore": "Files excluded from git",
    "Makefile": "Build/task automation",
    "README.md": "Project documentation",
    "LICENSE": "Software license",
    "CHANGELOG.md": "Version history",
    "conftest.py": "Pytest shared test fixtures",
    "manage.py": "Django management commands",
    "wsgi.py": "WSGI entry point",
    "asgi.py": "ASGI entry point",
    "alembic.ini": "Database migration config",
    ".github": "GitHub Actions and config",
    "tests": "Test suite",
    "docs": "Documentation",
    "migrations": "Database migrations",
    "static": "Static assets (CSS, JS, images)",
    "templates": "HTML templates",
}


def _detect_project_type(target: Path) -> str:
    """Detect what kind of project this is."""
    indicators: list[str] = []

    # Check for framework markers
    py_files = list(target.rglob("*.py"))
    all_content = ""
    for f in py_files[:20]:  # sample first 20 files
        try:
            all_content += f.read_text(encoding="utf-8", errors="replace") + "\n"
        except OSError:
            continue

    if (target / "manage.py").exists() or "django" in all_content.lower():
        indicators.append("Django web app")
    if "flask" in all_content.lower() and "Flask(" in all_content:
        indicators.append("Flask web app")
    if "fastapi" in all_content.lower() and "FastAPI(" in all_content:
        indicators.append("FastAPI web API")
    if "streamlit" in all_content.lower():
        indicators.append("Streamlit data app")
    if (target / "setup.py").exists() or (target / "pyproject.toml").exists():
        indicators.append("Python package/library")
    if "typer" in all_content.lower() and "Typer(" in all_content:
        indicators.append("CLI tool")
    if (target / "package.json").exists():
        indicators.append("Node.js project")
    if (target / "go.mod").exists():
        indicators.append("Go module")
    if (target / "Cargo.toml").exists():
        indicators.append("Rust crate")
    if (target / "pom.xml").exists() or (target / "build.gradle").exists() or (target / "build.gradle.kts").exists():
        indicators.append("Java project")
    if (target / "Gemfile").exists():
        indicators.append("Ruby project")
    if (target / "composer.json").exists():
        indicators.append("PHP project")
    if (target / "Dockerfile").exists():
        indicators.append("Dockerized")

    if indicators:
        return ", ".join(indicators)

    # Fall back to the dominant detected language
    langs = detect_languages(discover_files(target, skip_tests=False))
    if langs:
        dominant = next(iter(langs))
        return f"{dominant.capitalize()} project"
    return "Python project"


def _get_dependencies(target: Path) -> list[tuple[str, str]]:
    """Extract dependencies across ecosystems and describe them in plain English."""
    import json

    from repomedic.analyzers.dependencies import parse_dep_name

    deps: list[str] = []

    # From pyproject.toml
    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            for dep in data.get("project", {}).get("dependencies", []):
                name = parse_dep_name(dep)
                deps.append(name.lower())
        except Exception as exc:
            logger.warning("Failed to parse pyproject.toml for explain: %s", exc)

    # From requirements.txt
    req = target / "requirements.txt"
    if req.is_file():
        try:
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    name = parse_dep_name(line)
                    if name.lower() not in deps:
                        deps.append(name.lower())
        except OSError as exc:
            logger.warning("Failed to read requirements.txt for explain: %s", exc)

    # From package.json
    pkg_json = target / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            for name in data.get("dependencies", {}):
                if name.lower() not in deps:
                    deps.append(name.lower())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse package.json for explain: %s", exc)

    # From Cargo.toml
    cargo = target / "Cargo.toml"
    if cargo.is_file():
        try:
            data = tomllib.loads(cargo.read_text(encoding="utf-8"))
            for name in data.get("dependencies", {}):
                if name.lower() not in deps:
                    deps.append(name.lower())
        except (tomllib.TOMLDecodeError, OSError) as exc:
            logger.warning("Failed to parse Cargo.toml for explain: %s", exc)

    result = []
    for dep in deps:
        desc = _DEP_DESCRIPTIONS.get(dep, "third-party package")
        result.append((dep, desc))
    return result


def _get_module_docstring(filepath: Path) -> str | None:
    """Extract the module docstring from a Python file."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
        return ast.get_docstring(tree)
    except Exception:
        return None


def _build_file_tree(target: Path, max_depth: int = 3) -> Tree:
    """Build an annotated file tree."""
    tree = Tree(f"[bold]{target.name}/[/]")
    _add_children(tree, target, target, depth=0, max_depth=max_depth)
    return tree


def _add_children(tree: Tree, directory: Path, root: Path, depth: int, max_depth: int) -> None:
    """Recursively add children to the tree."""
    if depth >= max_depth:
        return

    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", ".ruff_cache", "dist", "build", ".egg-info"}
    entries = sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))

    for entry in entries:
        if entry.name in skip or entry.name.startswith(".") and entry.name not in (".env", ".env.example", ".gitignore", ".github"):
            continue

        name = entry.name
        desc = _KNOWN_PATHS.get(name, "")

        if entry.is_dir():
            if not desc:
                # Check for __init__.py docstring
                init = entry / "__init__.py"
                if init.is_file():
                    docstring = _get_module_docstring(init)
                    if docstring:
                        desc = docstring.split("\n")[0][:60]
            label = f"[bold blue]{name}/[/]"
            if desc:
                label += f"  [dim]{desc}[/]"
            branch = tree.add(label)
            _add_children(branch, entry, root, depth + 1, max_depth)
        else:
            if not desc and entry.suffix == ".py":
                docstring = _get_module_docstring(entry)
                if docstring:
                    desc = docstring.split("\n")[0][:60]
            label = name
            if desc:
                label += f"  [dim]{desc}[/]"
            tree.add(label)


def collect_explain(target: Path) -> dict:
    """Gather project explanation data without printing anything."""
    files = discover_files(target, skip_tests=False)
    return {
        "target": str(target),
        "project_type": _detect_project_type(target),
        "languages": detect_languages(files),
        "dependencies": _get_dependencies(target),
        "file_count": len(files),
    }


def render_explain(data: dict, target: Path, out: Console | None = None) -> None:
    """Render collected explain data as rich panels/tables."""
    out = out or console
    langs = ", ".join(f"{name} ({count} files)" for name, count in data["languages"].items()) or "none detected"
    out.print(Panel(
        f"[bold]Project Type:[/] {data['project_type']}\n"
        f"[bold]Languages:[/] {langs}\n"
        f"[bold]Location:[/] {target}",
        title="[bold]Project Overview[/]",
        border_style="cyan",
    ))

    deps = data["dependencies"]
    if deps:
        table = Table(title="Dependencies (what this project uses)", show_header=True, header_style="bold", expand=True)
        table.add_column("Package", min_width=15, style="bold")
        table.add_column("What it does", min_width=30)

        for name, desc in deps:
            table.add_row(name, desc)

        out.print()
        out.print(table)

    out.print()
    out.print("[bold]Project Structure:[/]")
    out.print(_build_file_tree(target))


def render_explain_markdown(data: dict) -> str:
    """Render the project brief as markdown — an agent onboarding document."""
    lines = [
        f"# Project Brief: `{data['target']}`",
        "",
        f"- **Type:** {data['project_type']}",
        f"- **Files:** {data['file_count']}",
    ]
    langs = ", ".join(f"{name} ({count})" for name, count in data["languages"].items())
    lines.append(f"- **Languages:** {langs or 'none detected'}")
    lines.append("")

    if data["dependencies"]:
        lines += ["## Dependencies", "", "| Package | Purpose |", "|---------|---------|"]
        for name, desc in data["dependencies"]:
            lines.append(f"| {name} | {desc} |")
        lines.append("")

    lines.append("*Generated by `repomedic explain`.*")
    return "\n".join(lines)


def run_explain(target: Path) -> dict:
    """Explain a project in plain English; print the report, return the data."""
    data = collect_explain(target)
    render_explain(data, target)
    return data
