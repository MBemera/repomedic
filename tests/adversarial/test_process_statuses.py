"""Regression tests for subprocess status confusion at analyzer boundaries."""

from __future__ import annotations

import pytest

import repomedic.analyzers.runtime as runtime_module
from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.utils.process import ProcessResult, ProcessStatus

pytestmark = pytest.mark.adversarial


@pytest.mark.parametrize(
    ("process_result", "expected_title"),
    [
        pytest.param(
            ProcessResult(
                status=ProcessStatus.ok,
                returncode=-1,
                stdout="",
                stderr="terminated by SIGHUP",
            ),
            "Script failed",
            id="signal-death",
        ),
        pytest.param(
            ProcessResult(
                status=ProcessStatus.timed_out,
                returncode=None,
                stdout="",
                stderr="Timed out after 3s",
            ),
            "Script timed out",
            id="timeout",
        ),
    ],
)
def test_signal_death_and_timeout_are_not_reported_as_missing_interpreters(
    make_project,
    monkeypatch: pytest.MonkeyPatch,
    process_result: ProcessResult,
    expected_title: str,
) -> None:
    project = make_project({"script.sh": "exit 0\n"})
    monkeypatch.setattr(
        runtime_module,
        "run",
        lambda *args, **kwargs: process_result,
    )

    result = RuntimeAnalyzer().analyze_script(
        str(project / "script.sh"),
        cwd=str(project),
        timeout=3,
    )

    assert not process_result.tool_missing
    assert result.error is None
    assert result.findings[0].title == expected_title
    assert "not found" not in result.findings[0].description.lower()


def test_signal_return_code_remains_a_real_process_failure(
    make_project,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = make_project({"script.sh": "exit 0\n"})
    signal_death = ProcessResult(
        status=ProcessStatus.ok,
        returncode=-1,
        stdout="",
        stderr="terminated by SIGHUP",
    )
    monkeypatch.setattr(
        runtime_module,
        "run",
        lambda *args, **kwargs: signal_death,
    )

    result = RuntimeAnalyzer().analyze_script(
        str(project / "script.sh"),
        cwd=str(project),
    )

    finding = result.findings[0]
    assert signal_death.ran
    assert finding.metadata["returncode"] == -1
    assert "code -1" in finding.description
