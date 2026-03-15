"""Tests for the runtime analyzer."""

from __future__ import annotations

from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.core.context import ScanContext


def test_not_applicable_by_default(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = RuntimeAnalyzer()
    assert not analyzer.is_applicable(ctx)


def test_analyze_script_success(tmp_path):
    script = tmp_path / "good.py"
    script.write_text("print('hello')\n")
    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script), cwd=str(tmp_path))
    assert len(result.findings) == 0


def test_analyze_script_failure(tmp_path):
    script = tmp_path / "bad.py"
    script.write_text("raise ValueError('test error')\n")
    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script), cwd=str(tmp_path))
    assert len(result.findings) >= 1
    assert result.findings[0].code == "RUN-002"
    assert "ValueError" in result.findings[0].title


def test_analyze_script_import_error(tmp_path):
    script = tmp_path / "missing_import.py"
    script.write_text("import nonexistent_module_xyz123\n")
    analyzer = RuntimeAnalyzer()
    result = analyzer.analyze_script(str(script), cwd=str(tmp_path))
    assert len(result.findings) >= 1
    assert "ModuleNotFoundError" in result.findings[0].title
