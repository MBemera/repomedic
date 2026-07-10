"""Headless debugger support for RepoMedic."""

from repomedic.debug.session import (
    CaptureBounds,
    CapturedFrame,
    DebugCapture,
    capture_python_crash,
)

__all__ = [
    "CaptureBounds",
    "CapturedFrame",
    "DebugCapture",
    "capture_python_crash",
]
