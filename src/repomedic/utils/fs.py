"""File discovery utilities with ignore patterns."""

from __future__ import annotations

from pathlib import Path

IGNORE_DIRS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    ".eggs",
    "*.egg-info",
    "dist",
    "build",
    ".claude",
    # Testing directories
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "spec",
}

def _is_test_file(name: str) -> bool:
    """Return True if the file looks like a test file."""
    base = name.lower()
    return (
        base.startswith("test_")
        or base.endswith("_test.py")
        or base.endswith("_test.js")
        or base.endswith("_test.ts")
        or base.endswith("_test.go")
        or base.endswith("_test.rs")
        or base.endswith(".spec.js")
        or base.endswith(".spec.ts")
    )

def _get_ignore_dirs(skip_tests: bool) -> set[str]:
    ignored = set(IGNORE_DIRS)
    if not skip_tests:
        ignored -= {"tests", "test", "__tests__", "fixtures", "spec"}
    return ignored

def discover_files(
    root: Path,
    extensions: set[str] | None = None,
    ignore_dirs: set[str] | None = None,
    skip_tests: bool = True,
    extra_ignore_dirs: set[str] | None = None,
) -> list[Path]:
    """Walk *root* and return files, skipping ignored directories and optionally test files."""
    ignored = ignore_dirs if ignore_dirs is not None else _get_ignore_dirs(skip_tests)
    if extra_ignore_dirs:
        ignored = ignored | extra_ignore_dirs
    results: list[Path] = []

    if not root.is_dir():
        return results

    for item in sorted(root.rglob("*")):
        # Only check parts relative to root, so explicit paths inside ignored dirs work
        rel_parts = item.relative_to(root).parts
        if any(part in ignored for part in rel_parts):
            continue
        if item.is_file():
            if skip_tests and _is_test_file(item.name):
                continue
            if extensions is None or item.suffix in extensions:
                results.append(item)

    return results
