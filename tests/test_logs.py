"""Tests for the log analyzer."""

from __future__ import annotations

from repomedic.analyzers.logs import LogAnalyzer
from repomedic.core.context import ScanContext


def test_error_lines_detected(make_project):
    project = make_project({
        "app.log": "2024-01-01 INFO Starting up\n2024-01-01 ERROR Database connection failed\n2024-01-01 ERROR Database connection failed\n",
    })
    ctx = ScanContext(str(project), skip_tests=False)
    analyzer = LogAnalyzer()
    result = analyzer.analyze(ctx)

    log_findings = [f for f in result.findings if f.code == "LOG-001"]
    assert len(log_findings) == 1
    assert "2 error(s)" in log_findings[0].title


def test_traceback_detected(make_project):
    project = make_project({
        "app.log": 'Traceback (most recent call last):\n  File "app.py", line 1\nValueError: bad\n',
    })
    ctx = ScanContext(str(project), skip_tests=False)
    analyzer = LogAnalyzer()
    result = analyzer.analyze(ctx)

    tb_findings = [f for f in result.findings if f.code == "LOG-002"]
    assert len(tb_findings) == 1


def test_clean_log(make_project):
    project = make_project({
        "app.log": "2024-01-01 INFO Starting up\n2024-01-01 INFO Ready\n",
    })
    ctx = ScanContext(str(project), skip_tests=False)
    analyzer = LogAnalyzer()
    result = analyzer.analyze(ctx)

    assert len(result.findings) == 0


def test_not_applicable_without_logs(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project), skip_tests=False)
    analyzer = LogAnalyzer()
    assert not analyzer.is_applicable(ctx)
