"""Tests for the static analyzer."""

from __future__ import annotations

from repomedic.analyzers.static import StaticAnalyzer
from repomedic.core.context import ScanContext


def test_syntax_error_detected(make_project):
    project = make_project({"broken.py": "def foo(\n"})
    ctx = ScanContext(str(project))
    analyzer = StaticAnalyzer()
    result = analyzer.analyze(ctx)

    assert len(result.findings) >= 1
    syntax_findings = [f for f in result.findings if f.code == "STATIC-001"]
    assert len(syntax_findings) == 1
    assert syntax_findings[0].severity.value == "error"
    assert syntax_findings[0].file_path == "broken.py"


def test_valid_python_no_syntax_errors(make_project):
    project = make_project({"good.py": "x = 1\nprint(x)\n"})
    ctx = ScanContext(str(project))
    analyzer = StaticAnalyzer()
    result = analyzer.analyze(ctx)

    syntax_findings = [f for f in result.findings if f.code == "STATIC-001"]
    assert len(syntax_findings) == 0


def test_not_applicable_without_python(make_project):
    project = make_project({"readme.txt": "hello\n"})
    ctx = ScanContext(str(project))
    analyzer = StaticAnalyzer()
    assert not analyzer.is_applicable(ctx)
