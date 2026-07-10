"""Python crash capture through a headless debugpy DAP session."""

from __future__ import annotations

import importlib.util
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Any

from repomedic.debug.dap import (
    DapClient,
    DapError,
    DapMessage,
    DapTimeoutError,
)
from repomedic.utils.process import kill_process_tree
from repomedic.utils.redact import redact_debug_variable, redact_sensitive_text

logger = logging.getLogger("repomedic")

LOOPBACK_HOST = "127.0.0.1"
ADAPTER_START_ATTEMPTS = 3
CONNECT_RETRY_SECONDS = 0.05
MAX_FRAMES = 100
MAX_VARIABLES_PER_FRAME = 200
MAX_VALUE_CHARS = 4000
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_VARIABLE_NAME_CHARS = 200


@dataclass(frozen=True)
class CaptureBounds:
    """Hard limits for debugger state retained in a capture."""

    max_frames: int = 20
    max_variables_per_frame: int = 25
    max_value_chars: int = 500
    max_output_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        limits = (
            ("max_frames", self.max_frames, MAX_FRAMES),
            (
                "max_variables_per_frame",
                self.max_variables_per_frame,
                MAX_VARIABLES_PER_FRAME,
            ),
            ("max_value_chars", self.max_value_chars, MAX_VALUE_CHARS),
            ("max_output_bytes", self.max_output_bytes, MAX_OUTPUT_BYTES),
        )
        for name, value, maximum in limits:
            if not 1 <= value <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")


@dataclass(frozen=True)
class CapturedFrame:
    """One debugger stack frame and its immediate local variables."""

    file: str
    line: int
    function: str
    locals: dict[str, str] = field(default_factory=dict)
    locals_truncated: bool = False


@dataclass(frozen=True)
class DebugCapture:
    """Bounded state captured at an uncaught Python exception."""

    exception_type: str
    message: str
    frames: list[CapturedFrame] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""


class DebugCaptureStatus(str, Enum):
    """Result state for one debugger-backed script execution."""

    unavailable = "unavailable"
    completed = "completed"
    captured = "captured"
    timed_out = "timed_out"
    failed = "failed"


@dataclass(frozen=True)
class DebugCaptureOutcome:
    """Execution result used by the runtime analyzer to avoid reruns."""

    status: DebugCaptureStatus
    capture: DebugCapture | None = None
    returncode: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""


@dataclass
class _DebugProcess:
    process: subprocess.Popen[bytes]
    stdout: _TailCollector
    stderr: _TailCollector


class _TailCollector:
    """Drain a byte stream while retaining only its bounded tail."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._buffer = bytearray()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        while chunk := self._stream.read(65536):
            with self._lock:
                self._buffer.extend(chunk)
                overflow = len(self._buffer) - self._limit
                if overflow > 0:
                    del self._buffer[:overflow]
        self._stream.close()

    def text(self) -> str:
        with self._lock:
            value = bytes(self._buffer).decode("utf-8", errors="replace")
        return redact_sensitive_text(value)[-self._limit :]

    def join(self) -> None:
        self._thread.join(timeout=2)


def capture_python_crash(
    script: str | Path,
    args: Sequence[str] | None = None,
    cwd: str | Path | None = None,
    timeout: float = 60,
    bounds: CaptureBounds | None = None,
) -> DebugCapture | None:
    """Capture an uncaught Python exception, returning ``None`` on fallback."""
    return capture_python_crash_outcome(
        script,
        args=args,
        cwd=cwd,
        timeout=timeout,
        bounds=bounds,
    ).capture


def capture_python_crash_outcome(
    script: str | Path,
    args: Sequence[str] | None = None,
    cwd: str | Path | None = None,
    timeout: float = 60,
    bounds: CaptureBounds | None = None,
) -> DebugCaptureOutcome:
    """Run one debugger session and report whether the target already ran."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not _debugpy_available():
        return _unavailable_outcome()

    capture_paths = _resolve_capture_paths(script, cwd)
    if capture_paths is None:
        return _unavailable_outcome()
    script_path, working_directory = capture_paths

    capture_bounds = bounds or CaptureBounds()
    deadline = time.monotonic() + timeout
    debug_process, connection = _start_capture_process(
        script_path,
        list(args or []),
        working_directory,
        deadline,
        capture_bounds,
    )
    if debug_process is None or connection is None:
        return _unavailable_outcome()

    return _capture_and_cleanup(debug_process, connection, deadline, capture_bounds)


def _unavailable_outcome() -> DebugCaptureOutcome:
    return DebugCaptureOutcome(status=DebugCaptureStatus.unavailable)


def _start_capture_process(
    script: Path,
    args: list[str],
    cwd: Path,
    deadline: float,
    bounds: CaptureBounds,
) -> tuple[_DebugProcess | None, socket.socket | None]:
    try:
        return _start_debug_process(script, args, cwd, deadline, bounds)
    except (OSError, subprocess.SubprocessError):
        logger.warning(
            "Python debugger could not start; falling back to traceback analysis"
        )
        return None, None


def _debugpy_available() -> bool:
    try:
        return importlib.util.find_spec("debugpy") is not None
    except (ImportError, ValueError):
        return False


def _resolve_capture_paths(
    script: str | Path,
    cwd: str | Path | None,
) -> tuple[Path, Path] | None:
    script_path = Path(script).expanduser().resolve()
    working_directory = Path(cwd).expanduser().resolve() if cwd else script_path.parent
    if not script_path.is_file() or not working_directory.is_dir():
        return None
    return script_path, working_directory


def _capture_and_cleanup(
    debug_process: _DebugProcess,
    connection: socket.socket,
    deadline: float,
    bounds: CaptureBounds,
) -> DebugCaptureOutcome:
    client = DapClient(connection)
    capture: DebugCapture | None = None
    status = DebugCaptureStatus.completed
    try:
        capture = _run_debug_session(client, debug_process.process, deadline, bounds)
        if capture is not None:
            status = DebugCaptureStatus.captured
    except DapTimeoutError:
        status = DebugCaptureStatus.timed_out
        logger.warning("Python debugger session timed out")
    except (DapError, OSError, FutureTimeoutError, ValueError):
        status = DebugCaptureStatus.failed
        logger.warning("Python debugger capture failed")
    finally:
        client.close()
        _finish_process(debug_process, deadline)

    stdout_tail = debug_process.stdout.text()
    stderr_tail = debug_process.stderr.text()
    capture = _capture_with_output(capture, stdout_tail, stderr_tail)
    return DebugCaptureOutcome(
        status=status,
        capture=capture,
        returncode=debug_process.process.returncode,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
    )


def _capture_with_output(
    capture: DebugCapture | None,
    stdout_tail: str,
    stderr_tail: str,
) -> DebugCapture | None:
    if capture is None:
        return None
    return DebugCapture(
        exception_type=capture.exception_type,
        message=capture.message,
        frames=capture.frames,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
    )


def _start_debug_process(
    script: Path,
    args: list[str],
    cwd: Path,
    deadline: float,
    bounds: CaptureBounds,
) -> tuple[_DebugProcess | None, socket.socket | None]:
    for _ in range(ADAPTER_START_ATTEMPTS):
        port = _probe_loopback_port()
        debug_process = _spawn_debug_process(script, args, cwd, port, bounds)
        connection = _connect_to_adapter(debug_process.process, port, deadline)
        if connection is not None:
            return debug_process, connection
        _finish_process(debug_process, deadline)
        if _remaining(deadline) <= 0:
            break
    return None, None


def _probe_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((LOOPBACK_HOST, 0))
        return int(probe.getsockname()[1])


def _spawn_debug_process(
    script: Path,
    args: list[str],
    cwd: Path,
    port: int,
    bounds: CaptureBounds,
) -> _DebugProcess:
    process = subprocess.Popen(
        _debug_command(script, args, port),
        **_debug_process_options(cwd),
    )
    assert process.stdout is not None
    assert process.stderr is not None
    return _DebugProcess(
        process=process,
        stdout=_TailCollector(process.stdout, bounds.max_output_bytes),
        stderr=_TailCollector(process.stderr, bounds.max_output_bytes),
    )


def _debug_command(script: Path, args: list[str], port: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "debugpy",
        "--listen",
        f"{LOOPBACK_HOST}:{port}",
        "--wait-for-client",
        str(script),
        *args,
    ]


def _debug_process_options(cwd: Path) -> dict[str, Any]:
    popen_kwargs: dict[str, Any] = {
        "cwd": str(cwd),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": dict(os.environ),
    }
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True
    return popen_kwargs


def _connect_to_adapter(
    process: subprocess.Popen[bytes],
    port: int,
    deadline: float,
) -> socket.socket | None:
    while process.poll() is None and _remaining(deadline) > 0:
        try:
            connection = socket.create_connection(
                (LOOPBACK_HOST, port),
                timeout=min(0.2, _remaining(deadline)),
            )
            connection.settimeout(None)
            return connection
        except OSError:
            time.sleep(min(CONNECT_RETRY_SECONDS, _remaining(deadline)))
    return None


def _run_debug_session(
    client: DapClient,
    process: subprocess.Popen[bytes],
    deadline: float,
    bounds: CaptureBounds,
) -> DebugCapture | None:
    client.request("initialize", _initialize_arguments(), timeout=_remaining(deadline))
    attach_future = client.request_async("attach", _attach_arguments())
    client.wait_for_event("initialized", timeout=_remaining(deadline))
    client.request(
        "setExceptionBreakpoints",
        {"filters": ["uncaught"]},
        timeout=_remaining(deadline),
    )
    client.request("configurationDone", {}, timeout=_remaining(deadline))
    _wait_for_response(attach_future, "attach", deadline)

    stopped = _wait_for_exception_stop(client, deadline)
    if stopped is None:
        if not _wait_for_process(process, deadline):
            raise DapTimeoutError("Timed out waiting for the debuggee to exit")
        return None
    capture = _capture_exception(client, stopped, deadline, bounds)
    _continue_process(client, stopped, deadline)
    _wait_for_process(process, deadline)
    return capture


def _initialize_arguments() -> DapMessage:
    return {
        "clientID": "repomedic",
        "clientName": "RepoMedic",
        "adapterID": "python",
        "pathFormat": "path",
        "linesStartAt1": True,
        "columnsStartAt1": True,
        "supportsVariableType": True,
        "supportsVariablePaging": True,
        "supportsRunInTerminalRequest": False,
        "locale": "en-US",
    }


def _attach_arguments() -> DapMessage:
    return {
        "name": "RepoMedic crash capture",
        "type": "python",
        "request": "attach",
        "justMyCode": False,
        "subProcess": False,
    }


def _wait_for_response(
    future: Future[DapMessage],
    command: str,
    deadline: float,
) -> DapMessage:
    try:
        return future.result(timeout=_remaining(deadline))
    except FutureTimeoutError as exc:
        future.cancel()
        raise DapTimeoutError(f"Timed out waiting for '{command}' response") from exc


def _wait_for_exception_stop(client: DapClient, deadline: float) -> DapMessage | None:
    terminal_events = {"stopped", "terminated", "exited"}
    while _remaining(deadline) > 0:
        event = client.wait_for_event(terminal_events, timeout=_remaining(deadline))
        if event.get("event") != "stopped":
            return None
        if _message_body(event).get("reason") == "exception":
            return event
    return None


def _capture_exception(
    client: DapClient,
    stopped: DapMessage,
    deadline: float,
    bounds: CaptureBounds,
) -> DebugCapture:
    thread_id = _thread_id(client, stopped, deadline)
    frames = _capture_frames(client, thread_id, deadline, bounds)
    response = client.request(
        "exceptionInfo",
        {"threadId": thread_id},
        timeout=_remaining(deadline),
    )
    body = _message_body(response)
    details = _optional_message(body.get("details"))
    exception_type = _bounded_text(
        str(details.get("typeName") or body.get("exceptionId") or "Exception"),
        MAX_VARIABLE_NAME_CHARS,
    )
    message = redact_sensitive_text(
        str(details.get("message") or body.get("description") or exception_type)
    )
    message = _bounded_text(message, bounds.max_value_chars)
    return DebugCapture(exception_type=exception_type, message=message, frames=frames)


def _thread_id(client: DapClient, stopped: DapMessage, deadline: float) -> int:
    value = _message_body(stopped).get("threadId")
    if isinstance(value, int):
        return value
    response = client.request("threads", {}, timeout=_remaining(deadline))
    threads = _message_list(_message_body(response).get("threads"), "threads")
    if not threads or not isinstance(threads[0].get("id"), int):
        raise DapError("Debugger did not identify the stopped thread")
    return int(threads[0]["id"])


def _capture_frames(
    client: DapClient,
    thread_id: int,
    deadline: float,
    bounds: CaptureBounds,
) -> list[CapturedFrame]:
    response = client.request(
        "stackTrace",
        {"threadId": thread_id, "startFrame": 0, "levels": bounds.max_frames},
        timeout=_remaining(deadline),
    )
    raw_frames = _message_list(
        _message_body(response).get("stackFrames"), "stackFrames"
    )
    frames: list[CapturedFrame] = []
    for raw_frame in raw_frames[: bounds.max_frames]:
        frame = _capture_frame(client, raw_frame, deadline, bounds)
        if frame is not None:
            frames.append(frame)
    return frames


def _capture_frame(
    client: DapClient,
    raw_frame: DapMessage,
    deadline: float,
    bounds: CaptureBounds,
) -> CapturedFrame | None:
    frame_id = raw_frame.get("id")
    if not isinstance(frame_id, int):
        return None
    local_values, truncated = _capture_locals(client, frame_id, deadline, bounds)
    source = _optional_message(raw_frame.get("source"))
    return CapturedFrame(
        file=_bounded_text(
            str(source.get("path") or source.get("name") or ""), MAX_VALUE_CHARS
        ),
        line=int(raw_frame.get("line") or 0),
        function=_bounded_text(
            str(raw_frame.get("name") or "<unknown>"),
            MAX_VARIABLE_NAME_CHARS,
        ),
        locals=local_values,
        locals_truncated=truncated,
    )


def _capture_locals(
    client: DapClient,
    frame_id: int,
    deadline: float,
    bounds: CaptureBounds,
) -> tuple[dict[str, str], bool]:
    scopes_response = client.request(
        "scopes",
        {"frameId": frame_id},
        timeout=_remaining(deadline),
    )
    reference = _locals_reference(scopes_response)
    if reference == 0:
        return {}, False
    response = client.request(
        "variables",
        {
            "variablesReference": reference,
            "start": 0,
            "count": bounds.max_variables_per_frame + 1,
        },
        timeout=_remaining(deadline),
    )
    variables = _message_list(_message_body(response).get("variables"), "variables")
    return _bounded_variables(variables, bounds)


def _locals_reference(scopes_response: DapMessage) -> int:
    scopes = _message_list(_message_body(scopes_response).get("scopes"), "scopes")
    preferred = next(
        (scope for scope in scopes if str(scope.get("name", "")).lower() == "locals"),
        None,
    )
    scope = preferred or next(
        (item for item in scopes if not item.get("expensive")), None
    )
    reference = scope.get("variablesReference") if scope else 0
    return reference if isinstance(reference, int) else 0


def _bounded_variables(
    variables: list[DapMessage],
    bounds: CaptureBounds,
) -> tuple[dict[str, str], bool]:
    values: dict[str, str] = {}
    visible = variables[: bounds.max_variables_per_frame]
    for variable in visible:
        raw_name = str(variable.get("name") or "<unnamed>")
        name = _bounded_text(
            raw_name,
            MAX_VARIABLE_NAME_CHARS,
        )
        value = str(variable.get("value") or "")
        value = redact_debug_variable(raw_name, value)
        if len(value) > bounds.max_value_chars:
            value = value[: bounds.max_value_chars] + "…"
        values[name] = value
    return values, len(variables) > bounds.max_variables_per_frame


def _continue_process(client: DapClient, stopped: DapMessage, deadline: float) -> None:
    thread_id = _message_body(stopped).get("threadId")
    if not isinstance(thread_id, int):
        return
    try:
        client.request(
            "continue", {"threadId": thread_id}, timeout=_remaining(deadline)
        )
    except DapError:
        pass


def _wait_for_process(process: subprocess.Popen[bytes], deadline: float) -> bool:
    remaining = _remaining(deadline)
    if remaining <= 0:
        return process.poll() is not None
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        return False
    return True


def _finish_process(debug_process: _DebugProcess, deadline: float) -> None:
    process = debug_process.process
    if process.poll() is None:
        kill_process_tree(process)
        try:
            process.wait(timeout=min(2.0, max(0.1, _remaining(deadline))))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    debug_process.stdout.join()
    debug_process.stderr.join()


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _message_body(message: DapMessage) -> DapMessage:
    return _optional_message(message.get("body"))


def _optional_message(value: Any) -> DapMessage:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise DapError("Debugger response body has an invalid shape")
    return value


def _message_list(value: Any, field_name: str) -> list[DapMessage]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise DapError(f"Debugger '{field_name}' field has an invalid shape")
    return value


def _bounded_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "…"
