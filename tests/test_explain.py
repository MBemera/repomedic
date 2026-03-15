"""Tests for the explain command."""

from __future__ import annotations

from repomedic.commands.explain import _detect_project_type, _get_dependencies, run_explain


def test_detect_django_project(tmp_path):
    (tmp_path / "manage.py").write_text("#!/usr/bin/env python\nimport django\n")
    result = _detect_project_type(tmp_path)
    assert "Django" in result


def test_detect_flask_project(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    result = _detect_project_type(tmp_path)
    assert "Flask" in result


def test_detect_cli_tool(tmp_path):
    (tmp_path / "cli.py").write_text("import typer\napp = Typer()\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    result = _detect_project_type(tmp_path)
    assert "CLI" in result


def test_detect_plain_python(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    result = _detect_project_type(tmp_path)
    assert "Python" in result


def test_get_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\ndependencies = ["flask>=2.0", "requests"]\n'
    )
    deps = _get_dependencies(tmp_path)
    names = [d[0] for d in deps]
    assert "flask" in names
    assert "requests" in names


def test_get_dependencies_with_descriptions(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\ndependencies = ["flask>=2.0"]\n'
    )
    deps = _get_dependencies(tmp_path)
    assert deps[0][1] != "third-party package"  # should have a known description


def test_run_explain(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\ndependencies = ["flask"]\n'
    )
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    result = run_explain(tmp_path)
    assert "project_type" in result
    assert "dependencies" in result
