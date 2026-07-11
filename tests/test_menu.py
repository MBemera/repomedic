"""Tests for the interactive startup menu and the agent handoff."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from repomedic.cli import app
from repomedic.commands import menu as menu_module
from repomedic.commands.menu import (
    AGENT_PROMPT,
    REPORT_FILENAME,
    agent_command,
    run_agent_handoff,
    run_menu,
)
from tests.cli_runner import create_cli_runner


def make_console() -> Console:
    return Console(file=StringIO(), force_terminal=False)


def make_ask(answers: list[str]):
    iterator = iter(answers)
    return lambda prompt: next(iterator)


def recording_dispatch(calls: list[list[str]], exit_code: int = 0):
    def dispatch(args: list[str]) -> int:
        calls.append(args)
        return exit_code

    return dispatch


def test_menu_quits_immediately():
    calls: list[list[str]] = []
    exit_code = run_menu(recording_dispatch(calls), make_console(), ask=make_ask(["q"]))
    assert exit_code == 0
    assert calls == []


def test_menu_dispatches_scan_of_current_folder():
    calls: list[list[str]] = []
    run_menu(recording_dispatch(calls), make_console(), ask=make_ask(["1", "q"]))
    assert calls == [["scan", "."]]


def test_menu_prompts_for_scan_target():
    calls: list[list[str]] = []
    run_menu(recording_dispatch(calls), make_console(), ask=make_ask(["2", "/some/path", "q"]))
    assert calls == [["scan", "/some/path"]]


def test_menu_unknown_choice_dispatches_nothing():
    calls: list[list[str]] = []
    console = make_console()
    run_menu(recording_dispatch(calls), console, ask=make_ask(["z", "q"]))
    assert calls == []
    assert "Unknown choice" in console.file.getvalue()


def test_menu_eof_exits_cleanly():
    def raising_ask(prompt: str) -> str:
        raise EOFError

    exit_code = run_menu(recording_dispatch([]), make_console(), ask=raising_ask)
    assert exit_code == 0


def test_agent_command_defaults_to_claude(monkeypatch):
    monkeypatch.delenv("REPOMEDIC_AGENT", raising=False)
    assert agent_command() == ["claude"]


def test_agent_command_env_override(monkeypatch):
    monkeypatch.setenv("REPOMEDIC_AGENT", "codex --full-auto")
    assert agent_command() == ["codex", "--full-auto"]


def test_handoff_rejects_missing_directory():
    calls: list[list[str]] = []
    exit_code = run_agent_handoff(
        recording_dispatch(calls), make_console(), make_ask(["/nonexistent-repomedic-target"])
    )
    assert exit_code == 2
    assert calls == []


def test_handoff_clean_scan_skips_launch(tmp_path, monkeypatch):
    def forbid_run(*args, **kwargs):
        raise AssertionError("agent must not launch when there is nothing to fix")

    monkeypatch.setattr(menu_module.subprocess, "run", forbid_run)
    calls: list[list[str]] = []
    exit_code = run_agent_handoff(
        recording_dispatch(calls, exit_code=0), make_console(), make_ask([str(tmp_path)])
    )
    assert exit_code == 0
    assert calls[0][0] == "scan"
    assert "--fail-on" in calls[0] and "warning" in calls[0]


def test_handoff_declined_confirmation_does_not_launch(tmp_path, monkeypatch):
    def forbid_run(*args, **kwargs):
        raise AssertionError("agent must not launch without explicit confirmation")

    monkeypatch.setattr(menu_module.subprocess, "run", forbid_run)
    exit_code = run_agent_handoff(
        recording_dispatch([], exit_code=1), make_console(), make_ask([str(tmp_path), "n"])
    )
    assert exit_code == 0


def test_handoff_confirmed_launches_agent_on_report(tmp_path, monkeypatch):
    launched: dict = {}

    class FakeCompleted:
        returncode = 0

    def fake_run(command, cwd=None):
        launched["command"] = command
        launched["cwd"] = cwd
        return FakeCompleted()

    monkeypatch.delenv("REPOMEDIC_AGENT", raising=False)
    monkeypatch.setattr(menu_module.subprocess, "run", fake_run)
    calls: list[list[str]] = []
    exit_code = run_agent_handoff(
        recording_dispatch(calls, exit_code=1), make_console(), make_ask([str(tmp_path), "y"])
    )

    assert exit_code == 0
    assert launched["command"] == ["claude", AGENT_PROMPT]
    assert launched["cwd"] == tmp_path.resolve()
    report_argument = calls[0][calls[0].index("--report-file") + 1]
    assert Path(report_argument) == tmp_path.resolve() / REPORT_FILENAME


def test_bare_invocation_opens_menu_on_tty(monkeypatch):
    monkeypatch.setattr(menu_module, "stdio_is_interactive", lambda: True)
    runner = create_cli_runner()
    result = runner.invoke(app, [], input="q\n")
    assert result.exit_code == 0
    assert "what do you want to do?" in result.output


def test_bare_invocation_scans_when_not_a_tty(tmp_path, monkeypatch):
    monkeypatch.setattr(menu_module, "stdio_is_interactive", lambda: False)
    monkeypatch.chdir(tmp_path)
    runner = create_cli_runner()
    result = runner.invoke(app, [])
    assert "what do you want to do?" not in result.output.lower()
