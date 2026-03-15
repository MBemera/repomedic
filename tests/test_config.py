"""Tests for the config analyzer."""

from __future__ import annotations

from repomedic.analyzers.config import ConfigAnalyzer
from repomedic.core.context import ScanContext


def test_pyproject_missing_name(make_project):
    project = make_project({
        "pyproject.toml": '[project]\nversion = "0.1.0"\n',
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    codes = [f.code for f in result.findings]
    assert "CFG-002" in codes  # missing name


def test_pyproject_missing_build_system(make_project):
    project = make_project({
        "pyproject.toml": '[project]\nname = "foo"\nversion = "0.1.0"\n',
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    codes = [f.code for f in result.findings]
    assert "CFG-003" in codes


def test_invalid_pyproject(make_project):
    project = make_project({
        "pyproject.toml": "this is not valid toml {{{\n",
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    codes = [f.code for f in result.findings]
    assert "CFG-001" in codes


def test_invalid_package_json(make_project):
    project = make_project({
        "package.json": "{ invalid json }",
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    codes = [f.code for f in result.findings]
    assert "CFG-004" in codes


def test_valid_config_no_issues(make_project):
    project = make_project({
        "pyproject.toml": '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n\n[project]\nname = "foo"\nversion = "1.0"\n',
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    assert len(result.findings) == 0
