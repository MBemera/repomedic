"""Debugger locals are untrusted repository data and must stay fenced."""

from __future__ import annotations

import re

import pytest

import repomedic.analyzers.runtime as runtime_module
from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.debug.session import (
    CapturedFrame,
    DebugCapture,
    DebugCaptureOutcome,
    DebugCaptureStatus,
)
from repomedic.models import ScanReport
from repomedic.output.markdown_output import render_fix_report
from tests.adversarial.payloads import DEBUG_LOCAL_PAYLOAD, longest_backtick_run

pytestmark = pytest.mark.adversarial

_FENCE_OPEN = re.compile(r"^(`{3,})[A-Za-z0-9_-]*$")


def test_debug_local_payload_is_inside_a_strictly_longer_fence(
    make_project,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = make_project({"app.py": "raise ValueError('boom')\n"})
    capture = DebugCapture(
        exception_type="ValueError",
        message="boom",
        frames=[
            CapturedFrame(
                file=str(project / "app.py"),
                line=1,
                function="main",
                locals={"payload": DEBUG_LOCAL_PAYLOAD},
            )
        ],
    )
    monkeypatch.setattr(
        runtime_module,
        "capture_python_crash_outcome",
        lambda *args, **kwargs: DebugCaptureOutcome(
            status=DebugCaptureStatus.captured,
            capture=capture,
            returncode=1,
        ),
    )

    result = RuntimeAnalyzer().analyze_script(
        str(project / "app.py"),
        cwd=str(project),
        debug=True,
    )
    report = ScanReport(target=str(project), results=[result])
    report.build_summary()
    markdown = render_fix_report(report, include_snippets=False)
    lines = markdown.splitlines()
    payload_line_index = next(
        index for index, line in enumerate(lines) if "DEBUG-LOCAL-CANARY" in line
    )

    opening_index = next(
        index
        for index in range(payload_line_index - 1, -1, -1)
        if _FENCE_OPEN.fullmatch(lines[index])
    )
    opening_match = _FENCE_OPEN.fullmatch(lines[opening_index])
    assert opening_match is not None
    fence = opening_match.group(1)
    closing_index = lines.index(fence, payload_line_index + 1)

    assert opening_index < payload_line_index < closing_index
    assert len(fence) > longest_backtick_run(DEBUG_LOCAL_PAYLOAD)
    assert not any(
        "DEBUG-LOCAL-CANARY" in line
        for line in lines[:opening_index] + lines[closing_index + 1 :]
    )
