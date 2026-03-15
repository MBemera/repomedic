"""Tests for the process utility module."""

from __future__ import annotations

from repomedic.utils.process import NOT_FOUND, TIMED_OUT, ProcessResult, run


def test_run_echo():
    result = run(["echo", "hello"])
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_run_command_not_found():
    result = run(["nonexistent-command-xyz123"])
    assert result.returncode == NOT_FOUND
    assert "Command not found" in result.stderr


def test_run_timeout():
    result = run(["sleep", "10"], timeout=1)
    assert result.returncode == TIMED_OUT
    assert "Timed out" in result.stderr


def test_run_with_cwd(tmp_path):
    result = run(["pwd"], cwd=str(tmp_path))
    assert result.returncode == 0
    assert str(tmp_path) in result.stdout


def test_process_result_fields():
    pr = ProcessResult(returncode=0, stdout="out", stderr="err")
    assert pr.returncode == 0
    assert pr.stdout == "out"
    assert pr.stderr == "err"


def test_returncode_less_than_zero_catches_both():
    """Both NOT_FOUND and TIMED_OUT are < 0."""
    assert NOT_FOUND < 0
    assert TIMED_OUT < 0
    assert NOT_FOUND != TIMED_OUT
