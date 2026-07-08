"""Tests for the semgrep analyzer."""

from __future__ import annotations

from unittest.mock import patch

from repomedic.analyzers.semgrep import SemgrepAnalyzer
from repomedic.core.context import ScanContext
from repomedic.utils.process import ProcessResult


def test_semgrep_not_installed_is_silent(make_project):
    """A missing optional tool must not pollute every report with findings."""
    project = make_project({"app.py": "print('hi')\n"})

    def fake_run(cmd, **kwargs):
        return ProcessResult(returncode=-1, stdout="", stderr="Command not found: semgrep")

    with patch("repomedic.analyzers.semgrep.run", side_effect=fake_run):
        ctx = ScanContext(str(project))
        analyzer = SemgrepAnalyzer()
        result = analyzer.analyze(ctx)

    assert result.findings == []
    assert result.error is None


def test_semgrep_applicable(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = SemgrepAnalyzer()
    assert analyzer.is_applicable(ctx)
