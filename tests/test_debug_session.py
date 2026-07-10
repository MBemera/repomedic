"""Tests for real Python crash capture through debugpy."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from repomedic.debug import session
from repomedic.debug.session import (
    CaptureBounds,
    DebugCaptureStatus,
    capture_python_crash,
    capture_python_crash_outcome,
)


def test_capture_bounds_reject_unbounded_values() -> None:
    with pytest.raises(ValueError, match="max_frames"):
        CaptureBounds(max_frames=0)
    with pytest.raises(ValueError, match="max_variables_per_frame"):
        CaptureBounds(max_variables_per_frame=201)


def test_missing_debugpy_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "app.py"
    script.write_text("raise ValueError('boom')\n")
    monkeypatch.setattr(session.importlib.util, "find_spec", lambda name: None)

    assert capture_python_crash(script, timeout=1) is None
    assert (
        capture_python_crash_outcome(script, timeout=1).status
        is DebugCaptureStatus.unavailable
    )


def test_debugger_start_failure_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "app.py"
    script.write_text("raise ValueError('boom')\n")
    monkeypatch.setattr(session, "_debugpy_available", lambda: True)

    def fail_start(*args, **kwargs):
        raise OSError("spawn failed")

    monkeypatch.setattr(session, "_start_debug_process", fail_start)

    assert capture_python_crash(script, timeout=1) is None


def test_variable_capture_is_bounded_and_redacted() -> None:
    variables = [
        {"name": "api_token", "value": "sensitive-test-value"},
        {"name": "ordinary", "value": "x" * 20},
        {"name": "extra", "value": "not retained"},
    ]
    bounds = CaptureBounds(max_variables_per_frame=2, max_value_chars=8)

    values, truncated = session._bounded_variables(variables, bounds)

    assert values["api_token"] == "[REDACTE…"
    assert values["ordinary"] == "xxxxxxxx…"
    assert "extra" not in values
    assert truncated is True


def test_variable_name_is_checked_before_display_truncation() -> None:
    secret_name = "x" * 220 + "_password"
    variables = [{"name": secret_name, "value": "unstructured-sensitive-value"}]

    values, _ = session._bounded_variables(variables, CaptureBounds())

    assert next(iter(values.values())) == "[REDACTED]"


def test_secret_inside_container_value_is_masked() -> None:
    variables = [
        {"name": "config", "value": "{'password': 'supersecret123'}"},
    ]

    values, _ = session._bounded_variables(variables, CaptureBounds())

    assert "supersecret123" not in values["config"]
    assert "supe…" in values["config"]


def test_real_debugpy_captures_uncaught_exception(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "crash.py"
    script.write_text(
        "ordinary_value = {'answer': 42}\n"
        "api_token = 'sensitive-test-value'\n"
        "print('password=unstructured-sensitive-value', flush=True)\n"
        "raise ValueError('expected crash')\n"
    )

    capture = capture_python_crash(
        script,
        cwd=tmp_path,
        timeout=15,
        bounds=CaptureBounds(max_frames=10, max_variables_per_frame=20),
    )

    assert capture is not None
    assert capture.exception_type == "ValueError"
    assert "expected crash" in capture.message
    user_frame = next(frame for frame in capture.frames if Path(frame.file) == script)
    assert user_frame.line == 4
    assert user_frame.locals["api_token"] == "[REDACTED]"
    assert "answer" in user_frame.locals["ordinary_value"]
    assert "unstructured-sensitive-value" not in capture.stdout_tail


def test_real_debugpy_reports_clean_completion(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "clean.py"
    script.write_text("print('completed', flush=True)\n")

    outcome = capture_python_crash_outcome(script, cwd=tmp_path, timeout=15)

    assert outcome.status is DebugCaptureStatus.completed
    assert outcome.capture is None
    assert outcome.returncode == 0
    assert "completed" in outcome.stdout_tail


def test_real_debugpy_timeout_kills_hanging_script(tmp_path: Path) -> None:
    pytest.importorskip("debugpy")
    script = tmp_path / "hang.py"
    script.write_text("while True:\n    pass\n")
    started = time.monotonic()

    outcome = capture_python_crash_outcome(script, cwd=tmp_path, timeout=3)

    assert outcome.status is DebugCaptureStatus.timed_out
    assert outcome.capture is None
    assert time.monotonic() - started < 6
