"""File discovery utilities with ignore patterns."""

from __future__ import annotations

import os
from pathlib import Path

# Default per-file read budget for analyzers that load whole files.
MAX_READ_BYTES = 1_048_576  # 1 MiB


def read_text_capped(path: Path, max_bytes: int = MAX_READ_BYTES) -> str | None:
    """Read a text file, or return None when oversized or unreadable.

    Analyzers use this instead of bare ``read_text()`` so a single huge
    (or unreadable) file can neither exhaust memory nor crash a check.
    """
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

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
    """Walk *root* and return files, skipping ignored directories and optionally test files.

    The walk never follows directory symlinks, and file symlinks are kept
    only when they resolve inside *root* — a link pointing outside the scan
    root (e.g. at ``~/.aws/credentials``) must never be read into findings
    or snippets. Ignored directories are pruned before descent.
    """
    ignored = ignore_dirs if ignore_dirs is not None else _get_ignore_dirs(skip_tests)
    if extra_ignore_dirs:
        ignored = ignored | extra_ignore_dirs
    results: list[Path] = []

    if not root.is_dir():
        return results

    root_resolved = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in ignored)
        for name in sorted(filenames):
            if skip_tests and _is_test_file(name):
                continue
            path = Path(dirpath) / name
            if extensions is not None and path.suffix not in extensions:
                continue
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=True)
                except OSError:
                    continue  # broken link — hygiene flags these separately
                if not resolved.is_relative_to(root_resolved):
                    continue  # escapes the scan root
                if not resolved.is_file():
                    continue
            elif not path.is_file():
                continue  # sockets, fifos, ...
            results.append(path)

    return results
