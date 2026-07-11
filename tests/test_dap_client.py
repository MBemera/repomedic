"""Protocol tests for the bounded headless DAP client."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable
from typing import Any, BinaryIO

import pytest

from repomedic.debug.dap import (
    DapClient,
    DapProtocolError,
    DapRequestError,
)

DapMessage = dict[str, Any]


def test_request_and_event_round_trip() -> None:
    def handler(server: socket.socket) -> None:
        reader = server.makefile("rb")
        request = _read_message(reader)
        assert request["command"] == "initialize"
        _send_message(server, {"seq": 1, "type": "event", "event": "initialized"})
        _send_message(
            server, _response_for(request, body={"supportsExceptionInfoRequest": True})
        )

    client, finish = _start_server(handler)
    try:
        response = client.request("initialize", {"clientID": "test"}, timeout=1)
        event = client.wait_for_event("initialized", timeout=1)
    finally:
        client.close()
        finish()

    assert response["body"]["supportsExceptionInfoRequest"] is True
    assert event["event"] == "initialized"


def test_out_of_order_responses_match_request_sequence() -> None:
    def handler(server: socket.socket) -> None:
        reader = server.makefile("rb")
        first = _read_message(reader)
        second = _read_message(reader)
        _send_message(server, _response_for(second, body={"value": "second"}))
        _send_message(server, _response_for(first, body={"value": "first"}))

    client, finish = _start_server(handler)
    try:
        first = client.request_async("first")
        second = client.request_async("second")
        assert first.result(timeout=1)["body"]["value"] == "first"
        assert second.result(timeout=1)["body"]["value"] == "second"
    finally:
        client.close()
        finish()


def test_wait_for_event_preserves_unmatched_events() -> None:
    def handler(server: socket.socket) -> None:
        _send_message(server, {"seq": 1, "type": "event", "event": "output"})
        _send_message(server, {"seq": 2, "type": "event", "event": "stopped"})

    client, finish = _start_server(handler)
    try:
        assert client.wait_for_event("stopped", timeout=1)["event"] == "stopped"
        assert client.wait_for_event("output", timeout=1)["event"] == "output"
    finally:
        client.close()
        finish()


def test_unsuccessful_response_raises_request_error() -> None:
    def handler(server: socket.socket) -> None:
        request = _read_message(server.makefile("rb"))
        response = _response_for(request, success=False)
        response["message"] = "attach rejected"
        _send_message(server, response)

    client, finish = _start_server(handler)
    try:
        with pytest.raises(DapRequestError, match="attach rejected"):
            client.request("attach", timeout=1)
    finally:
        client.close()
        finish()


def test_oversized_adapter_message_fails_closed() -> None:
    def handler(server: socket.socket) -> None:
        server.sendall(b"Content-Length: 100\r\n\r\n")

    client, finish = _start_server(handler, max_message_bytes=32)
    try:
        with pytest.raises(DapProtocolError, match="size limit"):
            client.wait_for_event(timeout=1)
    finally:
        client.close()
        finish()


def test_duplicate_content_length_fails_closed() -> None:
    def handler(server: socket.socket) -> None:
        server.sendall(b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}")

    client, finish = _start_server(handler)
    try:
        with pytest.raises(DapProtocolError, match="duplicate"):
            client.wait_for_event(timeout=1)
    finally:
        client.close()
        finish()


def _start_server(
    handler: Callable[[socket.socket], None],
    **client_options: Any,
) -> tuple[DapClient, Callable[[], None]]:
    client_socket, server_socket = socket.socketpair()
    errors: list[BaseException] = []

    def run_handler() -> None:
        try:
            handler(server_socket)
        except (
            BaseException
        ) as exc:  # surfaced by finish, never swallowed in the thread
            errors.append(exc)
        finally:
            server_socket.close()

    thread = threading.Thread(target=run_handler, daemon=True)
    thread.start()

    def finish() -> None:
        thread.join(timeout=2)
        assert not thread.is_alive()
        if errors:
            raise errors[0]

    return DapClient(client_socket, **client_options), finish


def _read_message(reader: BinaryIO) -> DapMessage:
    header = reader.readline()
    assert header.lower().startswith(b"content-length:")
    content_length = int(header.split(b":", 1)[1].strip())
    assert reader.readline() == b"\r\n"
    return json.loads(reader.read(content_length))


def _send_message(server: socket.socket, message: DapMessage) -> None:
    body = json.dumps(message, separators=(",", ":")).encode()
    server.sendall(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)


def _response_for(
    request: DapMessage,
    *,
    success: bool = True,
    body: DapMessage | None = None,
) -> DapMessage:
    response: DapMessage = {
        "seq": 100 + int(request["seq"]),
        "type": "response",
        "request_seq": request["seq"],
        "success": success,
        "command": request["command"],
    }
    if body is not None:
        response["body"] = body
    return response
