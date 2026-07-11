"""Safe real-process helpers for CLI contract tests."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from tests.cli_runner import create_cli_runner

CONTRACT_ROOT = Path(__file__).parent
FIXTURES_ROOT = CONTRACT_ROOT / "fixtures"
REPOSITORY_ROOT = CONTRACT_ROOT.parents[1]
CLI_BOOTSTRAP = "from repomedic.cli import app; app()"


def _build_subprocess_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
        if name in os.environ
    }
    environment.update(
        {
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": str(REPOSITORY_ROOT / "src"),
            "PYTHONUNBUFFERED": "1",
        }
    )
    environment["PATH"] = ""
    return environment


@pytest.fixture
def run_cli_process() -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run the public Typer app in an isolated child process."""

    def run_cli(
        arguments: Sequence[str],
        *,
        input_text: str | None = None,
        cwd: Path = FIXTURES_ROOT,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-c", CLI_BOOTSTRAP, *arguments]
        return subprocess.run(
            command,
            cwd=cwd,
            env=_build_subprocess_environment(),
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    return run_cli


@pytest.fixture
def cli_runner():
    """Create the Click-version-compatible public CLI runner."""
    return create_cli_runner()
