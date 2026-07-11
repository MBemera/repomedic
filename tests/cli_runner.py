"""Click-version-compatible CLI test runner."""

from __future__ import annotations

import inspect

from typer.testing import CliRunner


def create_cli_runner() -> CliRunner:
    """Create a runner with separate stderr capture across Click versions."""
    if "mix_stderr" in inspect.signature(CliRunner).parameters:
        return CliRunner(mix_stderr=False)
    return CliRunner()
