"""Tests for the process utility module."""

from __future__ import annotations

import sys
import time

import pytest

from repomedic.utils.process import (
    ENV_ALLOWLIST,
    ProcessResult,
    ProcessStatus,
    isolated_env,
    run,
)


def test_run_echo():
    result = run(["echo", "hello"])
    assert result.status is ProcessStatus.ok
    assert result.ok
    assert result.ran
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_run_command_not_found():
    result = run(["nonexistent-command-xyz123"])
    assert result.status is ProcessStatus.not_found
    assert result.tool_missing
    assert not result.ran
    assert not result.ok
    assert result.returncode is None
    assert "Command not found" in result.stderr


def test_run_timeout():
    start = time.monotonic()
    result = run(["sleep", "10"], timeout=1)
    assert time.monotonic() - start < 5
    assert result.status is ProcessStatus.timed_out
    assert not result.ran
    assert not result.ok
    assert result.returncode is None
    assert "Timed out" in result.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_run_timeout_kills_process_group():
    """A timeout must take down children spawned by the command, not just the shell."""
    # The shell spawns a sleeping child; killing only the shell would leave it behind.
    start = time.monotonic()
    result = run(["bash", "-c", "sleep 30 & wait"], timeout=1)
    assert result.status is ProcessStatus.timed_out
    # If the process group kill failed, wait() above would have blocked ~30s.
    assert time.monotonic() - start < 10


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_run_signal_death_is_not_tool_missing():
    """A tool killed by a signal ran and crashed — it is not 'not installed'."""
    result = run(["bash", "-c", "kill -SEGV $$"])
    assert result.status is ProcessStatus.ok
    assert result.ran
    assert not result.ok
    assert not result.tool_missing
    assert result.returncode == -11


def test_run_with_cwd(tmp_path):
    result = run(["pwd"], cwd=str(tmp_path))
    assert result.ok
    assert str(tmp_path) in result.stdout


def test_run_output_capped():
    result = run(
        ["bash", "-c", "yes x | head -c 100000"],
        max_output_bytes=1000,
    )
    assert result.ran
    assert result.truncated
    assert len(result.stdout.encode()) <= 1000


def test_run_small_output_not_truncated():
    result = run(["echo", "hello"])
    assert not result.truncated


def test_env_isolated_by_default(monkeypatch):
    monkeypatch.setenv("FAKE_SECRET_TOKEN", "hunter2")
    result = run(["bash", "-c", 'echo "[${FAKE_SECRET_TOKEN}]"'])
    assert result.ok
    assert "hunter2" not in result.stdout


def test_env_inherit_mode(monkeypatch):
    monkeypatch.setenv("FAKE_SECRET_TOKEN", "hunter2")
    result = run(["bash", "-c", 'echo "[${FAKE_SECRET_TOKEN}]"'], env_mode="inherit")
    assert result.ok
    assert "hunter2" in result.stdout


def test_extra_env_passes_through():
    result = run(["bash", "-c", 'echo "$EXTRA_VAR"'], extra_env={"EXTRA_VAR": "value42"})
    assert result.ok
    assert "value42" in result.stdout


def test_isolated_env_allowlist_only(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leaky")
    env = isolated_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert all(k in ENV_ALLOWLIST for k in env)


def test_process_result_fields():
    pr = ProcessResult(status=ProcessStatus.ok, returncode=0, stdout="out", stderr="err")
    assert pr.ok
    assert pr.stdout == "out"
    assert pr.stderr == "err"
    assert not pr.truncated
