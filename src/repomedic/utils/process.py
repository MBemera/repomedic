"""Subprocess wrappers with timeout and JSON parsing."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("repomedic")

# Sentinel return codes for non-subprocess errors
NOT_FOUND = -1
TIMED_OUT = -2


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


def run(
    cmd: list[str],
    *,
    cwd: str | None = None,
    timeout: int = 30,
    check: bool = False,
) -> ProcessResult:
    """Run a subprocess with timeout, returning structured result."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return ProcessResult(returncode=NOT_FOUND, stdout="", stderr=f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return ProcessResult(returncode=TIMED_OUT, stdout="", stderr=f"Timed out after {timeout}s")

    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, proc.stdout, proc.stderr
        )

    return ProcessResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
