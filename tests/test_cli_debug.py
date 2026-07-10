"""CLI contract tests for debugger-backed runtime analysis."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repomedic.cli import app

runner = CliRunner(mix_stderr=False)


def test_debug_command_clean_script_exits_zero(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "clean.py"
    script.write_text("print('ok')\n")

    result = runner.invoke(app, ["debug", str(script), "--timeout", "15"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["summary"]["total_findings"] == 0


def test_debug_command_returns_run_004_json(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "crash.py"
    script.write_text(
        "visible = 42\n"
        "api_token = 'sensitive-test-value'\n"
        "raise ValueError('expected crash')\n"
    )

    result = runner.invoke(
        app,
        ["debug", str(script), "--timeout", "15", "--max-vars", "5", "-o", "json"],
    )

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    finding = report["results"][0]["findings"][0]
    assert finding["code"] == "RUN-004"
    assert finding["file_path"] == "crash.py"
    assert finding["line"] == 3
    assert finding["metadata"]["debug"]["exception"]["type"] == "ValueError"
    frame = finding["metadata"]["debug"]["frames"][0]
    assert len(frame["locals"]) <= 5
    assert frame["locals"]["api_token"] == "[REDACTED]"


def test_run_debug_renders_fenced_debug_state(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "crash.py"
    script.write_text("payload = '``` forged'\nraise RuntimeError('boom')\n")

    result = runner.invoke(
        app,
        ["run", str(script), "--debug", "--timeout", "15", "-o", "markdown"],
    )

    assert result.exit_code == 1
    assert "`RUN-004`" in result.stdout
    assert "**Debug state:**" in result.stdout
    assert "````json" in result.stdout


def test_debug_timeout_returns_promptly(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "hang.py"
    script.write_text("while True:\n    pass\n")
    started = time.monotonic()

    result = runner.invoke(app, ["debug", str(script), "--timeout", "2", "-o", "json"])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["results"][0]["findings"][0]["code"] == "RUN-001"
    assert time.monotonic() - started < 5


def test_invalid_output_does_not_execute_script(tmp_path: Path) -> None:
    script = tmp_path / "side_effect.py"
    marker = tmp_path / "marker.txt"
    script.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
    )

    result = runner.invoke(app, ["debug", str(script), "-o", "yaml"])

    assert result.exit_code == 2
    assert "invalid --output" in result.stderr
    assert not marker.exists()
