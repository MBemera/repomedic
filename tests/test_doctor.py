"""Tests for the doctor command."""

from __future__ import annotations


from repomedic.commands.doctor import _check_tool, collect_doctor


def test_check_tool_found():
    name, version, status = _check_tool("echo", ["echo", "v1.0"])
    assert status == "OK"
    assert "v1.0" in version


def test_check_tool_not_found():
    name, version, status = _check_tool("missing", ["nonexistent-command-xyz"])
    assert status == "MISSING"
    assert "not found" in version


def test_collect_doctor_basic(tmp_path):
    # Create a minimal project
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    result = collect_doctor(tmp_path)
    assert result.schema_version == 1
    assert len(result.checks) > 0
    assert any(check.name == "debugpy" for check in result.checks)


def test_collect_doctor_detects_missing_venv(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    result = collect_doctor(tmp_path)
    venv_checks = [c for c in result.checks if "Virtual env" in c.name]
    assert len(venv_checks) == 1
    assert venv_checks[0].status == "MISSING"


def test_collect_doctor_detects_venv(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    (tmp_path / ".venv").mkdir()
    result = collect_doctor(tmp_path)
    venv_checks = [c for c in result.checks if "Virtual env" in c.name]
    assert len(venv_checks) == 1
    assert venv_checks[0].status == "OK"
