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
        "README.md": "# foo\n",
        "LICENSE": "MIT\n",
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    assert len(result.findings) == 0


def test_data_file_syntax_errors(make_project):
    project = make_project({
        "README.md": "# foo\n",
        "LICENSE": "MIT\n",
        "config/settings.json": '{"key": "value",}',
        "config/app.toml": "not = valid = toml\n",
        "config/good.json": '{"key": "value"}',
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    syntax_findings = [f for f in result.findings if f.code == "CFG-010"]
    bad_files = {f.file_path for f in syntax_findings}
    assert "config/settings.json" in bad_files
    assert "config/app.toml" in bad_files
    assert "config/good.json" not in bad_files


def test_yaml_syntax_error(make_project):
    pytest = __import__("pytest")
    pytest.importorskip("yaml")
    project = make_project({
        "README.md": "# foo\n",
        "LICENSE": "MIT\n",
        "ci.yaml": "key: value\n  bad_indent: [unclosed\n",
    })
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    syntax_findings = [f for f in result.findings if f.code == "CFG-010"]
    assert any(f.file_path == "ci.yaml" for f in syntax_findings)


def test_missing_readme_and_license(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = ConfigAnalyzer()
    result = analyzer.analyze(ctx)

    codes = [f.code for f in result.findings]
    assert "CFG-011" in codes  # no README
    assert "CFG-012" in codes  # no LICENSE
