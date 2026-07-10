"""Subprocess wrappers: timeouts, bounded output capture, env isolation.

Every external tool RepoMedic invokes goes through :func:`run`. The wrapper
enforces three safety properties:

- **Distinct statuses.** A tool that is missing, timed out, or failed to
  start is reported via :class:`ProcessStatus`, never via fake return codes.
  (The previous sentinel ints ``-1``/``-2`` collided with real signal deaths:
  a linter killed by SIGHUP also returns ``-1``.)
- **Bounded capture.** stdout/stderr are capped (1 MiB per stream by
  default) so a tool that floods output cannot exhaust memory.
- **Isolated environment.** By default children see only an allowlisted
  environment — secrets like ``AWS_*`` or ``GITHUB_TOKEN`` never reach
  repo-controlled tools. Pass ``env_mode="inherit"`` only when the user
  explicitly asked to run their own code (``repomedic run``).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import IO, Any, Literal

logger = logging.getLogger("repomedic")

# Placeholder in a run_json_tool command that is replaced with a temporary
# report path the tool writes its JSON to (for tools without stdout JSON).
JSON_REPORT_PLACEHOLDER = "{json_report}"

# Environment variables allowed through to child processes in isolated mode.
# Everything needed for toolchains to function; nothing that carries secrets.
ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "TERM",
    "SYSTEMROOT", "COMSPEC", "PATHEXT",                       # windows
    "VIRTUAL_ENV", "PYTHONIOENCODING",                        # python tools
    "GOPATH", "GOCACHE", "GOMODCACHE", "GOFLAGS",             # go
    "CARGO_HOME", "RUSTUP_HOME",                              # rust
    "NPM_CONFIG_CACHE",                                       # node
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",                  # proxies
    "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
)

MAX_CAPTURE_BYTES = 1_048_576  # 1 MiB per stream


class ProcessStatus(str, Enum):
    ok = "ok"                          # started and exited (any code, incl. signal deaths)
    not_found = "not_found"            # executable missing
    timed_out = "timed_out"            # killed by our timeout
    failed_to_start = "failed_to_start"  # PermissionError / OSError at spawn


@dataclass(frozen=True)
class ProcessResult:
    status: ProcessStatus
    returncode: int | None  # real exit code only when status is ok, else None
    stdout: str
    stderr: str
    truncated: bool = False

    @property
    def ran(self) -> bool:
        """The process actually started and exited on its own."""
        return self.status is ProcessStatus.ok

    @property
    def ok(self) -> bool:
        """The process ran and exited 0."""
        return self.status is ProcessStatus.ok and self.returncode == 0

    @property
    def tool_missing(self) -> bool:
        return self.status is ProcessStatus.not_found


def isolated_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal child environment from the allowlist."""
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOWLIST}
    if extra:
        env.update(extra)
    return env


def _read_capped(stream: IO[bytes], limit: int, chunks: list[bytes], state: dict[str, bool]) -> None:
    """Reader-thread body: keep the first *limit* bytes, drain and count the rest."""
    kept = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        if kept < limit:
            take = chunk[: limit - kept]
            chunks.append(take)
            kept += len(take)
            if len(take) < len(chunk):
                state["truncated"] = True
        else:
            state["truncated"] = True
    stream.close()


def _kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill the child and (on POSIX) its whole process group."""
    if sys.platform != "win32":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    proc.kill()


def run(
    cmd: list[str],
    *,
    cwd: str | None = None,
    timeout: int = 30,
    check: bool = False,
    env_mode: Literal["isolated", "inherit"] = "isolated",
    extra_env: dict[str, str] | None = None,
    max_output_bytes: int = MAX_CAPTURE_BYTES,
) -> ProcessResult:
    """Run a subprocess with timeout, bounded capture, and env isolation."""
    if env_mode == "isolated":
        env = isolated_env(extra_env)
    else:
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)

    popen_kwargs: dict = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "env": env,
    }
    if sys.platform != "win32":
        # Own process group, so a timeout kill takes wrapper children
        # (npx -> node, cargo -> rustc, ...) down with the parent.
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except FileNotFoundError:
        return ProcessResult(
            status=ProcessStatus.not_found, returncode=None,
            stdout="", stderr=f"Command not found: {cmd[0]}",
        )
    except OSError as exc:
        return ProcessResult(
            status=ProcessStatus.failed_to_start, returncode=None,
            stdout="", stderr=f"Failed to start {cmd[0]}: {exc}",
        )

    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    state = {"truncated": False}
    readers = [
        threading.Thread(target=_read_capped, args=(proc.stdout, max_output_bytes, out_chunks, state), daemon=True),
        threading.Thread(target=_read_capped, args=(proc.stderr, max_output_bytes, err_chunks, state), daemon=True),
    ]
    for t in readers:
        t.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        _kill_process_tree(proc)
        proc.wait()
        for t in readers:
            t.join(timeout=5)
        return ProcessResult(
            status=ProcessStatus.timed_out, returncode=None,
            stdout=b"".join(out_chunks).decode("utf-8", errors="replace"),
            stderr=f"Timed out after {timeout}s",
            truncated=state["truncated"],
        )

    for t in readers:
        t.join(timeout=5)

    stdout = b"".join(out_chunks).decode("utf-8", errors="replace")
    stderr = b"".join(err_chunks).decode("utf-8", errors="replace")

    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, stdout, stderr)

    return ProcessResult(
        status=ProcessStatus.ok,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=state["truncated"],
    )


def run_json_tool(
    cmd: list[str],
    *,
    cwd: str | None = None,
    timeout: int = 30,
) -> tuple[Any | None, ProcessResult]:
    """Run a tool that emits JSON and parse it.

    JSON is read from stdout, or — when *cmd* contains
    :data:`JSON_REPORT_PLACEHOLDER` — from a temporary report file whose
    path is substituted for the placeholder and removed afterwards.

    Returns ``(data, result)``; ``data`` is ``None`` when the tool did not
    run or produced no valid JSON, and ``result`` carries the status so
    callers can distinguish "tool missing" from "no output".
    """
    report_path: str | None = None
    if JSON_REPORT_PLACEHOLDER in cmd:
        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="repomedic_")
        os.close(fd)
        cmd = [report_path if part == JSON_REPORT_PLACEHOLDER else part for part in cmd]

    try:
        result = run(cmd, cwd=cwd, timeout=timeout)
        if not result.ran:
            return None, result

        if report_path is not None:
            try:
                raw = Path(report_path).read_text(encoding="utf-8")
            except OSError:
                return None, result
        else:
            raw = result.stdout

        if not raw.strip():
            return None, result
        try:
            return json.loads(raw), result
        except json.JSONDecodeError:
            return None, result
    finally:
        if report_path is not None:
            Path(report_path).unlink(missing_ok=True)
