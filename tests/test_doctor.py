"""Tests for the doctor command."""

from __future__ import annotations

from unittest.mock import patch

from repomedic.commands.doctor import _check_tool, run_doctor
from repomedic.utils.process import ProcessResult


def test_check_tool_found():
    name, version, status = _check_tool("echo", ["echo", "v1.0"])
    assert status == "OK"
    assert "v1.0" in version


def test_check_tool_not_found():
    name, version, status = _check_tool("missing", ["nonexistent-command-xyz"])
    assert status == "MISSING"
    assert "not found" in version


def test_run_doctor_basic(tmp_path):
    # Create a minimal project
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    result = run_doctor(tmp_path)
    assert "checks" in result
    assert "fix_commands" in result
    assert len(result["checks"]) > 0


def test_run_doctor_detects_missing_venv(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    result = run_doctor(tmp_path)
    venv_checks = [c for c in result["checks"] if "Virtual env" in c[0]]
    assert len(venv_checks) == 1
    assert venv_checks[0][2] == "MISSING"


def test_run_doctor_detects_venv(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    (tmp_path / ".venv").mkdir()
    result = run_doctor(tmp_path)
    venv_checks = [c for c in result["checks"] if "Virtual env" in c[0]]
    assert len(venv_checks) == 1
    assert venv_checks[0][2] == "OK"
