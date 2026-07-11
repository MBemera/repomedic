"""Small, bounded Debug Adapter Protocol client.

DAP uses JSON messages framed by an HTTP-style ``Content-Length`` header.
This client handles request correlation and event delivery while a dedicated
reader thread drains the adapter socket.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections import deque
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from typing import Any

DapMessage = dict[str, Any]

MAX_DAP_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_DAP_HEADER_BYTES = 16 * 1024
MAX_QUEUED_EVENTS = 1024


class DapError(RuntimeError):
    """Base error for DAP transport and request failures."""


class DapProtocolError(DapError):
    """The adapter sent an invalid or unsafe protocol message."""


class DapConnectionClosed(DapError):
    """The adapter connection closed before an operation completed."""


class DapRequestError(DapError):
    """The adapter returned an unsuccessful response."""


class DapTimeoutError(DapError):
    """A DAP request or event wait exceeded its deadline."""


class DapClient:
    """Thread-safe DAP client over an already-connected TCP socket."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        max_message_bytes: int = MAX_DAP_MESSAGE_BYTES,
        max_queued_events: int = MAX_QUEUED_EVENTS,
    ) -> None:
        if max_message_bytes <= 0 or max_queued_events <= 0:
            raise ValueError("DAP bounds must be positive")

        self._connection = connection
        self._reader = connection.makefile("rb")
        self._max_message_bytes = max_message_bytes
        self._max_queued_events = max_queued_events
        self._write_lock = threading.Lock()
        self._state_changed = threading.Condition()
        self._pending: dict[int, Future[DapMessage]] = {}
        self._events: deque[DapMessage] = deque()
        self._next_sequence = 1
        self._closed = False
        self._failure: DapError | None = None
        self._reader_thread = threading.Thread(
            target=self._read_messages,
            name="repomedic-dap-reader",
            daemon=True,
        )
        self._reader_thread.start()

    def request_async(
        self,
        command: str,
        arguments: DapMessage | None = None,
    ) -> Future[DapMessage]:
        """Send a request and return a future for its response."""
        sequence, future = self._register_request()
        message: DapMessage = {
            "seq": sequence,
            "type": "request",
            "command": command,
        }
        if arguments is not None:
            message["arguments"] = arguments

        try:
            self._send_message(message)
        except (OSError, DapError) as exc:
            self._fail_connection(DapConnectionClosed(str(exc)))
        return future

    def request(
        self,
        command: str,
        arguments: DapMessage | None = None,
        *,
        timeout: float | None = None,
    ) -> DapMessage:
        """Send a request and wait for its successful response."""
        future = self.request_async(command, arguments)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError as exc:
            future.cancel()
            raise DapTimeoutError(
                f"Timed out waiting for '{command}' response"
            ) from exc

    def wait_for_event(
        self,
        event: str | set[str] | None = None,
        *,
        timeout: float | None = None,
    ) -> DapMessage:
        """Wait for one named event, one of a set, or the next event."""
        event_names = {event} if isinstance(event, str) else event
        deadline = None if timeout is None else time.monotonic() + timeout

        with self._state_changed:
            while True:
                queued = self._take_event(event_names)
                if queued is not None:
                    return queued
                self._raise_if_unavailable()
                self._state_changed.wait(timeout=self._remaining(deadline))
                if deadline is not None and time.monotonic() >= deadline:
                    raise DapTimeoutError("Timed out waiting for debugger event")

    def close(self) -> None:
        """Close the socket and fail any operations still in flight."""
        self._fail_connection(DapConnectionClosed("DAP client closed"))
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._connection.close()
        self._reader.close()
        if threading.current_thread() is not self._reader_thread:
            self._reader_thread.join(timeout=1)

    def _register_request(self) -> tuple[int, Future[DapMessage]]:
        with self._state_changed:
            self._raise_if_unavailable()
            sequence = self._next_sequence
            self._next_sequence += 1
            future: Future[DapMessage] = Future()
            self._pending[sequence] = future
            return sequence, future

    def _send_message(self, message: DapMessage) -> None:
        body = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if len(body) > self._max_message_bytes:
            raise DapProtocolError("Outgoing DAP message exceeds the size limit")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        with self._write_lock:
            self._connection.sendall(header + body)

    def _read_messages(self) -> None:
        try:
            while True:
                self._dispatch_message(self._read_message())
        except EOFError:
            self._fail_connection(DapConnectionClosed("Debug adapter disconnected"))
        except (OSError, ValueError, DapError) as exc:
            error = exc if isinstance(exc, DapError) else DapProtocolError(str(exc))
            self._fail_connection(error)

    def _read_message(self) -> DapMessage:
        content_length = self._read_content_length()
        body = self._reader.read(content_length)
        if len(body) != content_length:
            raise EOFError
        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DapProtocolError("Adapter sent invalid JSON") from exc
        if not isinstance(message, dict):
            raise DapProtocolError("Adapter message must be a JSON object")
        return message

    def _read_content_length(self) -> int:
        content_length: int | None = None
        header_bytes = 0
        while True:
            line = self._reader.readline(MAX_DAP_HEADER_BYTES + 1)
            if not line:
                raise EOFError
            header_bytes += len(line)
            if header_bytes > MAX_DAP_HEADER_BYTES:
                raise DapProtocolError("DAP header exceeds the size limit")
            if line in (b"\r\n", b"\n"):
                break
            name, separator, value = line.partition(b":")
            if not separator:
                raise DapProtocolError("Malformed DAP header")
            if name.strip().lower() == b"content-length":
                if content_length is not None:
                    raise DapProtocolError(
                        "DAP message has duplicate Content-Length headers"
                    )
                content_length = self._parse_content_length(value)
        if content_length is None:
            raise DapProtocolError("DAP message is missing Content-Length")
        return content_length

    def _parse_content_length(self, value: bytes) -> int:
        try:
            content_length = int(value.strip())
        except ValueError as exc:
            raise DapProtocolError("Invalid DAP Content-Length") from exc
        if not 0 <= content_length <= self._max_message_bytes:
            raise DapProtocolError("DAP message exceeds the size limit")
        return content_length

    def _dispatch_message(self, message: DapMessage) -> None:
        message_type = message.get("type")
        if message_type == "response":
            self._resolve_response(message)
            return
        if message_type == "event":
            self._queue_event(message)
            return
        if message_type == "request":
            self._reject_reverse_request(message)
            return
        raise DapProtocolError("Adapter sent a message with an unknown type")

    def _resolve_response(self, message: DapMessage) -> None:
        request_sequence = message.get("request_seq")
        if not isinstance(request_sequence, int):
            raise DapProtocolError("DAP response is missing request_seq")
        with self._state_changed:
            future = self._pending.pop(request_sequence, None)
        if future is None or future.done():
            return
        if message.get("success") is False:
            detail = str(message.get("message") or "Debugger request failed")
            future.set_exception(DapRequestError(detail))
            return
        future.set_result(message)

    def _queue_event(self, message: DapMessage) -> None:
        if not isinstance(message.get("event"), str):
            raise DapProtocolError("DAP event is missing its name")
        with self._state_changed:
            if len(self._events) >= self._max_queued_events:
                self._events.popleft()
            self._events.append(message)
            self._state_changed.notify_all()

    def _reject_reverse_request(self, message: DapMessage) -> None:
        request_sequence = message.get("seq")
        command = message.get("command")
        if not isinstance(request_sequence, int) or not isinstance(command, str):
            raise DapProtocolError("Malformed adapter reverse request")
        response: DapMessage = {
            "seq": self._reserve_sequence(),
            "type": "response",
            "request_seq": request_sequence,
            "success": False,
            "command": command,
            "message": "RepoMedic does not support adapter reverse requests",
        }
        self._send_message(response)

    def _reserve_sequence(self) -> int:
        with self._state_changed:
            sequence = self._next_sequence
            self._next_sequence += 1
            return sequence

    def _take_event(self, event_names: set[str] | None) -> DapMessage | None:
        for index, message in enumerate(self._events):
            if event_names is None or message.get("event") in event_names:
                del self._events[index]
                return message
        return None

    def _raise_if_unavailable(self) -> None:
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise DapConnectionClosed("DAP client is closed")

    def _fail_connection(self, error: DapError) -> None:
        pending: list[Future[DapMessage]] = []
        with self._state_changed:
            if self._closed:
                return
            self._closed = True
            self._failure = error
            pending = list(self._pending.values())
            self._pending.clear()
            self._state_changed.notify_all()
        for future in pending:
            if not future.done():
                future.set_exception(error)

    @staticmethod
    def _remaining(deadline: float | None) -> float | None:
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())
