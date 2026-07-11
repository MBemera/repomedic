"""Tests for the semgrep analyzer."""

from __future__ import annotations

from unittest.mock import patch

from repomedic.analyzers.semgrep import SemgrepAnalyzer
from repomedic.core.context import ScanContext
from repomedic.utils.process import ProcessResult, ProcessStatus


def test_semgrep_not_installed_is_silent(make_project):
    """A missing optional tool must not pollute every report with findings."""
    project = make_project({"app.py": "print('hi')\n"})

    def fake_run_json_tool(cmd, **kwargs):
        return None, ProcessResult(
            status=ProcessStatus.not_found,
            returncode=None,
            stdout="",
            stderr="Command not found: semgrep",
        )

    with patch("repomedic.analyzers.semgrep.run_json_tool", side_effect=fake_run_json_tool):
        ctx = ScanContext(str(project))
        analyzer = SemgrepAnalyzer()
        result = analyzer.analyze(ctx)

    assert result.findings == []
    assert result.error is None


def test_semgrep_findings_in_ignored_dirs_are_filtered(make_project):
    """Semgrep walks the tree itself, so excludes must be re-applied to its results."""
    project = make_project({"app.py": "print('hi')\n"})

    def fake_run_json_tool(cmd, **kwargs):
        data = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "path": "vendored/lib.py",
                    "start": {"line": 1, "col": 1},
                    "extra": {"severity": "ERROR", "message": "eval detected"},
                },
                {
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1},
                    "extra": {"severity": "ERROR", "message": "eval detected"},
                },
            ]
        }
        return data, ProcessResult(status=ProcessStatus.ok, returncode=0, stdout="", stderr="")

    with patch("repomedic.analyzers.semgrep.run_json_tool", side_effect=fake_run_json_tool):
        ctx = ScanContext(str(project), extra_ignore_dirs={"vendored"})
        result = SemgrepAnalyzer().analyze(ctx)

    assert [f.file_path for f in result.findings] == ["app.py"]


def test_semgrep_applicable(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = SemgrepAnalyzer()
    assert analyzer.is_applicable(ctx)
