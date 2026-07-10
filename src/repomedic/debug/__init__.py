"""Headless debugger support for RepoMedic."""

from repomedic.debug.session import (
    CaptureBounds,
    CapturedFrame,
    DebugCapture,
    DebugCaptureOutcome,
    DebugCaptureStatus,
    capture_python_crash,
    capture_python_crash_outcome,
)

__all__ = [
    "CaptureBounds",
    "CapturedFrame",
    "DebugCapture",
    "DebugCaptureOutcome",
    "DebugCaptureStatus",
    "capture_python_crash",
    "capture_python_crash_outcome",
]
