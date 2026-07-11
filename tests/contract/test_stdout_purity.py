"""Real-subprocess stdout isolation for machine and agent protocols."""

from __future__ import annotations

import json

import pytest

from tests.contract.conftest import FIXTURES_ROOT

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


def test_mcp_stdout_contains_only_json_rpc_messages(run_cli_process) -> None:
    pytest.importorskip("mcp")
    from mcp.types import LATEST_PROTOCOL_VERSION

    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "repomedic-contract", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    input_text = "".join(f"{json.dumps(message)}\n" for message in messages)

    result = run_cli_process(["mcp"], input_text=input_text, timeout=20)
    responses = [json.loads(line) for line in result.stdout.splitlines() if line]

    assert result.returncode == 0
    assert [response["id"] for response in responses] == [1, 2]
    assert all(response["jsonrpc"] == "2.0" for response in responses)
    assert all("result" in response for response in responses)
