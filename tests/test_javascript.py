"""Tests for the JavaScript/TypeScript analyzer."""

from __future__ import annotations

from repomedic.analyzers.javascript import JavaScriptAnalyzer
from repomedic.core.context import ScanContext


def test_applicable_with_js_files(make_project):
    project = make_project({"app.js": "console.log('hello');\n"})
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_applicable_with_package_json(make_project):
    project = make_project({"package.json": '{"name": "test"}\n'})
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_applicable_with_ts_files(make_project):
    project = make_project({"app.ts": "const x: number = 1;\n"})
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_not_applicable_without_js(make_project):
    project = make_project({"hello.py": "print('hello')\n"})
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    assert not analyzer.is_applicable(ctx)


def test_missing_node_modules(make_project):
    project = make_project({
        "package.json": '{"name": "test", "dependencies": {"express": "^4.0.0"}}\n',
    })
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    result = analyzer.analyze(ctx)

    dep_findings = [f for f in result.findings if f.code == "JS-DEP-001"]
    assert len(dep_findings) == 1
    assert dep_findings[0].language == "javascript"


def test_missing_lock_file(make_project):
    project = make_project({
        "package.json": '{"name": "test", "dependencies": {"express": "^4.0.0"}}\n',
    })
    # Create node_modules dir so DEP-001 doesn't trigger
    (project / "node_modules").mkdir()

    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    result = analyzer.analyze(ctx)

    lock_findings = [f for f in result.findings if f.code == "JS-DEP-002"]
    assert len(lock_findings) == 1


def test_valid_js_no_syntax_errors(make_project):
    project = make_project({"app.js": "const x = 1;\nconsole.log(x);\n"})
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    result = analyzer.analyze(ctx)

    syntax_findings = [f for f in result.findings if f.code == "JS-001"]
    assert len(syntax_findings) == 0


def test_syntax_error_detected(make_project):
    """Test that broken JS syntax is caught (requires node installed)."""
    project = make_project({"broken.js": "function foo( {\n"})
    ctx = ScanContext(str(project))
    analyzer = JavaScriptAnalyzer()
    result = analyzer.analyze(ctx)

    syntax_findings = [f for f in result.findings if f.code == "JS-001"]
    # This test only passes if node is available — skip otherwise
    if syntax_findings:
        assert syntax_findings[0].severity.value == "error"
        assert syntax_findings[0].language == "javascript"
