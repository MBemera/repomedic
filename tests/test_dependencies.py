"""Tests for the dependency analyzer."""

from __future__ import annotations

from unittest.mock import patch

from repomedic.analyzers.dependencies import DependencyAnalyzer, parse_dep_name
from repomedic.core.context import ScanContext
from repomedic.utils.process import ProcessResult, ProcessStatus


def test_parse_dep_name():
    assert parse_dep_name("requests>=2.0") == "requests"
    assert parse_dep_name("flask[async]>=2.0") == "flask"
    assert parse_dep_name("numpy==1.24.0") == "numpy"
    assert parse_dep_name("simple-package") == "simple-package"
    assert parse_dep_name("pkg<3.0,>=1.0") == "pkg"


def test_missing_package_detected(make_project):
    """When a target venv exists and a package is missing, DEP-002 is raised."""
    import os
    project = make_project({
        "requirements.txt": "nonexistent-package-xyz123==1.0.0\n",
        "app.py": "print('hi')\n",
    })

    # Create a fake venv with a python binary
    venv_bin = project / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    fake_python = venv_bin / "python"
    fake_python.write_text("#!/bin/sh\n")
    os.chmod(fake_python, 0o755)

    # Mock the pip list call to return empty
    def fake_run(cmd, **kwargs):
        if "pip" in cmd and "list" in cmd:
            return ProcessResult(status=ProcessStatus.ok, returncode=0, stdout="[]", stderr="")
        return ProcessResult(status=ProcessStatus.not_found, returncode=None, stdout="", stderr="")

    with patch("repomedic.analyzers.dependencies.run", side_effect=fake_run):
        ctx = ScanContext(str(project))
        analyzer = DependencyAnalyzer()
        result = analyzer.analyze(ctx)

    dep_findings = [f for f in result.findings if f.code == "DEP-002"]
    assert len(dep_findings) == 1
    assert "nonexistent-package-xyz123" in dep_findings[0].title


def test_no_issues_without_requirements(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = DependencyAnalyzer()
    result = analyzer.analyze(ctx)

    dep_findings = [f for f in result.findings if f.code == "DEP-002"]
    assert len(dep_findings) == 0


def test_no_venv_detected(make_project):
    """Without a venv dir and with pyproject.toml, DEP-001 info is raised."""
    project = make_project({
        "pyproject.toml": '[project]\nname = "test"\ndependencies = ["requests"]\n',
        "app.py": "print('hi')\n",
    })
    ctx = ScanContext(str(project))
    analyzer = DependencyAnalyzer()
    result = analyzer.analyze(ctx)

    dep_001 = [f for f in result.findings if f.code == "DEP-001"]
    assert len(dep_001) == 1


def test_venv_exists_no_missing_deps(make_project):
    """When all deps are installed, no DEP-002 findings."""
    import os
    project = make_project({
        "requirements.txt": "requests>=2.0\n",
        "app.py": "print('hi')\n",
    })

    venv_bin = project / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    fake_python = venv_bin / "python"
    fake_python.write_text("#!/bin/sh\n")
    os.chmod(fake_python, 0o755)

    def fake_run(cmd, **kwargs):
        if "pip" in cmd and "list" in cmd:
            return ProcessResult(
                status=ProcessStatus.ok,
                returncode=0,
                stdout='[{"name": "requests", "version": "2.31.0"}]',
                stderr="",
            )
        return ProcessResult(status=ProcessStatus.not_found, returncode=None, stdout="", stderr="")

    with patch("repomedic.analyzers.dependencies.run", side_effect=fake_run):
        ctx = ScanContext(str(project))
        analyzer = DependencyAnalyzer()
        result = analyzer.analyze(ctx)

    dep_findings = [f for f in result.findings if f.code == "DEP-002"]
    assert len(dep_findings) == 0
