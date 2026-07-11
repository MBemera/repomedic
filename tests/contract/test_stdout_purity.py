"""Real-subprocess stdout isolation for machine and agent protocols."""

from __future__ import annotations

import json
import subprocess
import sys
import threading

import pytest

from tests.contract.conftest import (
    CLI_BOOTSTRAP,
    FIXTURES_ROOT,
    _build_subprocess_environment,
)

PROJECTS_ROOT = FIXTURES_ROOT / "projects"


def _decode_one_json_document(stdout: str) -> dict:
    document, end_index = json.JSONDecoder().raw_decode(stdout)
    assert stdout[end_index:].strip() == ""
    assert isinstance(document, dict)
    return document


def test_scan_json_is_one_document_and_progress_is_on_stderr(run_cli_process) -> None:
    result = run_cli_process(
        [
            "scan",
            str(PROJECTS_ROOT / "broken"),
            "-a",
            "config",
            "--no-exec",
            "-o",
            "json",
        ]
    )

    payload = _decode_one_json_document(result.stdout)
    assert result.returncode == 0
    assert payload["schema_version"] == 3
    assert "Scanning " in result.stderr
    assert "Scanning " not in result.stdout


def test_sniff_stdout_contains_only_the_markdown_report(run_cli_process) -> None:
    result = run_cli_process(
        [
            "sniff",
            str(PROJECTS_ROOT / "broken"),
            "-a",
            "config",
            "--no-exec",
            "--no-snippets",
        ]
    )

    assert result.returncode == 1
    assert result.stdout.startswith("---\ntool: repomedic\n")
    assert "## Findings by File" in result.stdout
    assert "Scanning " in result.stderr
    assert "Scanning " not in result.stdout
    assert "\x1b[" not in result.stdout


def test_mcp_stdout_contains_only_json_rpc_messages() -> None:
    # A well-behaved MCP client reads each response before sending more and
    # keeps stdin open until it has everything. Writing all requests and
    # closing stdin in one shot races the SDK's EOF shutdown against the
    # in-flight tools/list handler (flaky on Python 3.11).
    pytest.importorskip("mcp")
    from mcp.types import LATEST_PROTOCOL_VERSION

    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "repomedic-contract", "version": "1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    tools_list = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    process = subprocess.Popen(
        [sys.executable, "-c", CLI_BOOTSTRAP, "mcp"],
        cwd=FIXTURES_ROOT,
        env=_build_subprocess_environment(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdin is not None and process.stdout is not None
    watchdog = threading.Timer(20, process.kill)
    watchdog.start()
    try:
        process.stdin.write(json.dumps(initialize) + "\n")
        process.stdin.flush()
        first = json.loads(process.stdout.readline())

        process.stdin.write(json.dumps(initialized) + "\n")
        process.stdin.write(json.dumps(tools_list) + "\n")
        process.stdin.flush()
        second = json.loads(process.stdout.readline())

        process.stdin.close()
        returncode = process.wait(timeout=10)
        remainder = process.stdout.read()
    finally:
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
            process.wait()

    assert returncode == 0
    responses = [first, second]
    assert [response["id"] for response in responses] == [1, 2]
    assert all(response["jsonrpc"] == "2.0" for response in responses)
    assert all("result" in response for response in responses)
    assert remainder.strip() == ""  # nothing but protocol on stdout
