"""Tests for the MCP server: tool functions directly, plus a client round trip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repomedic import mcp_server


def test_scan_tool_returns_structured_report(make_project):
    project = make_project({"app.py": "import os\nprint(os.name)\n"})
    payload = mcp_server.scan(str(project))

    assert set(payload) == {"exit_code", "fail_on", "report"}
    assert payload["report"]["schema_version"] == 3
    assert payload["report"]["target"] == str(project)


def test_scan_tool_defaults_to_no_exec(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    payload = mcp_server.scan(str(project))
    assert payload["report"]["exec_allowed"] is False


def test_fix_report_tool_returns_markdown(make_project):
    project = make_project({"app.py": "import os\nprint(os.name)\n"})
    report = mcp_server.fix_report(str(project))
    assert report.startswith("---")
    assert "tool: repomedic" in report


def test_fix_preview_tool_is_always_dry_run(make_project):
    project = make_project({"app.py": "x=1\n"})
    payload = mcp_server.fix_preview(str(project))
    assert payload["dry_run"] is True
    assert all(a["status"] != "FIXED" for a in payload["actions"])


def test_run_script_tool_reports_crash(make_project):
    project = make_project({"boom.py": "raise ValueError('nope')\n"})
    payload = mcp_server.run_script(str(project / "boom.py"))

    assert payload["exit_code"] == 1
    codes = [
        f["code"]
        for result in payload["report"]["results"]
        for f in result["findings"]
    ]
    assert codes, "expected at least one runtime finding"


def test_run_script_tool_rejects_non_file(tmp_path: Path):
    with pytest.raises(ValueError):
        mcp_server.run_script(str(tmp_path))


def test_doctor_explain_and_list_analyzers_are_typed(make_project):
    project = make_project({"app.py": "x=1\n"})

    doctor = mcp_server.doctor(str(project))
    assert doctor["tool"] == "repomedic" and doctor["checks"]

    explain = mcp_server.explain(str(project))
    assert explain["schema_version"] == 1

    analyzers = mcp_server.list_analyzers()
    assert len(analyzers["analyzers"]) >= 10


def test_baseline_write_tool(make_project):
    project = make_project({"app.py": "import os\n"})
    payload = mcp_server.baseline_write(str(project))

    baseline_path = Path(payload["path"])
    assert baseline_path.is_file()
    assert json.loads(baseline_path.read_text())["schema_version"] == 1


def test_local_dir_validation():
    with pytest.raises(ValueError):
        mcp_server.doctor("/nonexistent/path/xyz")


def test_mcp_client_round_trip(make_project):
    """In-process stdio-equivalent round trip through a real MCP session."""
    pytest.importorskip("mcp")
    import anyio
    from mcp.shared.memory import create_connected_server_and_client_session

    project = make_project({"app.py": "import os\nprint(os.name)\n"})
    server = mcp_server.build_server()

    async def round_trip() -> tuple[list[str], dict]:
        async with create_connected_server_and_client_session(
            server._mcp_server
        ) as session:
            listed = await session.list_tools()
            result = await session.call_tool("scan", {"target": str(project)})
            assert not result.isError
            payload = json.loads(result.content[0].text)
            return [t.name for t in listed.tools], payload

    tool_names, payload = anyio.run(round_trip)

    assert {
        "scan",
        "fix_report",
        "run_script",
        "doctor",
        "explain",
        "fix_preview",
        "baseline_write",
        "list_analyzers",
    } <= set(tool_names)
    assert payload["report"]["schema_version"] == 3
    assert payload["report"]["exec_allowed"] is False
