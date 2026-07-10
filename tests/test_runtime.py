"""Tests for the runtime analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

import repomedic.analyzers.runtime as runtime_module
from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.core.context import ScanContext
from repomedic.debug.session import (
    CapturedFrame,
    DebugCapture,
    DebugCaptureOutcome,
    DebugCaptureStatus,
)
from repomedic.utils.process import ProcessResult, ProcessStatus


def test_not_applicable_by_default(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = RuntimeAnalyzer()
    assert not analyzer.is_applicable(ctx)


def test_analyze_script_success(tmp_path):
    script = tmp_path / "good.py"
    script.write_text("print('hello')\n")
    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script), cwd=str(tmp_path))
    assert len(result.findings) == 0


def test_analyze_script_failure(tmp_path):
    script = tmp_path / "bad.py"
    script.write_text("raise ValueError('test error')\n")
    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script), cwd=str(tmp_path))
    assert len(result.findings) >= 1
    assert result.findings[0].code == "RUN-002"
    assert "ValueError" in result.findings[0].title


def test_analyze_script_import_error(tmp_path):
    script = tmp_path / "missing_import.py"
    script.write_text("import nonexistent_module_xyz123\n")
    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script), cwd=str(tmp_path))
    assert len(result.findings) >= 1
    assert "ModuleNotFoundError" in result.findings[0].title


def test_debug_capture_emits_run_004_at_deepest_user_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "app.py"
    helper = tmp_path / "helper.py"
    script.write_text("raise ValueError('boom')\n")
    helper.write_text("raise ValueError('boom')\n")
    capture = DebugCapture(
        exception_type="ValueError",
        message="boom",
        frames=[
            CapturedFrame(
                file="/venv/site-packages/library.py",
                line=50,
                function="wrapper",
            ),
            CapturedFrame(
                file=str(helper),
                line=1,
                function="explode",
                locals={"value": "42"},
            ),
            CapturedFrame(file=str(script), line=1, function="main"),
        ],
    )
    outcome = DebugCaptureOutcome(
        status=DebugCaptureStatus.captured,
        capture=capture,
        returncode=1,
    )
    monkeypatch.setattr(
        runtime_module, "capture_python_crash_outcome", lambda *a, **k: outcome
    )

    result = RuntimeAnalyzer().analyze_script(
        str(script), cwd=str(tmp_path), debug=True
    )

    finding = result.findings[0]
    assert finding.code == "RUN-004"
    assert finding.file_path == "helper.py"
    assert finding.line == 1
    assert [frame["file"] for frame in finding.metadata["debug"]["frames"]] == [
        "helper.py",
        "app.py",
    ]


def test_debug_unavailable_falls_back_to_one_plain_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "app.py"
    script.write_text("print('ok')\n")
    unavailable = DebugCaptureOutcome(status=DebugCaptureStatus.unavailable)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        runtime_module,
        "capture_python_crash_outcome",
        lambda *args, **kwargs: unavailable,
    )

    def fake_run(command, **kwargs):
        calls.append(command)
        return ProcessResult(ProcessStatus.ok, 0, "ok\n", "")

    monkeypatch.setattr(runtime_module, "run", fake_run)

    result = RuntimeAnalyzer().analyze_script(
        str(script), cwd=str(tmp_path), debug=True
    )

    assert result.findings == []
    assert len(calls) == 1


def test_completed_debug_session_does_not_execute_script_again(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "app.py"
    script.write_text("print('ok')\n")
    completed = DebugCaptureOutcome(
        status=DebugCaptureStatus.completed,
        returncode=0,
        stdout_tail="ok\n",
    )
    monkeypatch.setattr(
        runtime_module,
        "capture_python_crash_outcome",
        lambda *args, **kwargs: completed,
    )
    monkeypatch.setattr(
        runtime_module,
        "run",
        lambda *args, **kwargs: pytest.fail("plain execution must not run"),
    )

    result = RuntimeAnalyzer().analyze_script(
        str(script), cwd=str(tmp_path), debug=True
    )

    assert result.findings == []


def test_debug_timeout_uses_requested_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "hang.py"
    script.write_text("while True: pass\n")
    timed_out = DebugCaptureOutcome(status=DebugCaptureStatus.timed_out)
    monkeypatch.setattr(
        runtime_module,
        "capture_python_crash_outcome",
        lambda *args, **kwargs: timed_out,
    )

    result = RuntimeAnalyzer().analyze_script(
        str(script), cwd=str(tmp_path), debug=True, timeout=7
    )

    finding = result.findings[0]
    assert finding.code == "RUN-001"
    assert finding.metadata["timeout_seconds"] == 7
    assert "7s" in finding.description


def test_plain_traceback_redacts_secret_from_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "app.py"
    script.write_text("raise RuntimeError('failed')\n")
    stderr = (
        f'Traceback (most recent call last):\n  File "{script}", line 1\n'
        "RuntimeError: password=unstructured-sensitive-value\n"
    )
    monkeypatch.setattr(
        runtime_module,
        "run",
        lambda *args, **kwargs: ProcessResult(ProcessStatus.ok, 1, "", stderr),
    )

    result = RuntimeAnalyzer().analyze_script(str(script), cwd=str(tmp_path))

    finding = result.findings[0]
    assert "unstructured-sensitive-value" not in finding.description
    assert "unst…" in finding.description
