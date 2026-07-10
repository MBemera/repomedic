"""Tests for the CLI-free scan service."""

from __future__ import annotations

import pytest

from repomedic.core.service import (
    ScanRequest,
    ScanServiceError,
    exit_code_for,
    run_scan,
)
from repomedic.models import ScanReport


def test_run_scan_roundtrip(make_project):
    project = make_project({"app.py": "def broken(:\n    pass\n"})
    outcome = run_scan(ScanRequest(target=str(project), fail_on="error"))
    assert outcome.report.summary.errors >= 1
    assert outcome.exit_code == 1
    assert not outcome.was_remote
    outcome.cleanup()  # no-op for local targets


def test_run_scan_clean_project(make_project):
    project = make_project({"app.py": "x = 1\n"})
    outcome = run_scan(ScanRequest(target=str(project), analyzers=["static"], fail_on="error"))
    assert outcome.exit_code == 0


def test_run_scan_never_prints(make_project, capsys):
    project = make_project({"app.py": "def broken(:\n"})
    run_scan(ScanRequest(target=str(project)))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_run_scan_progress_callback(make_project):
    project = make_project({"app.py": "x = 1\n"})
    messages: list[str] = []
    run_scan(ScanRequest(target=str(project)), progress=messages.append)
    assert any("Scanning" in m for m in messages)


def test_run_scan_bad_target():
    with pytest.raises(ScanServiceError) as exc_info:
        run_scan(ScanRequest(target="/nonexistent/path/xyz"))
    assert exc_info.value.exit_code == 2


def test_run_scan_unknown_analyzer(make_project):
    project = make_project({"app.py": "x = 1\n"})
    with pytest.raises(ScanServiceError, match="unknown analyzer"):
        run_scan(ScanRequest(target=str(project), analyzers=["nope"]))


def test_run_scan_bad_severity(make_project):
    project = make_project({"app.py": "x = 1\n"})
    with pytest.raises(ScanServiceError, match="min_severity"):
        run_scan(ScanRequest(target=str(project), min_severity="fatal"))


def test_run_scan_changed_requires_git(make_project):
    project = make_project({"app.py": "x = 1\n"})
    with pytest.raises(ScanServiceError, match="git repository"):
        run_scan(ScanRequest(target=str(project), changed=True))


def test_exit_code_policy():
    report = ScanReport(target=".")
    assert exit_code_for(report, "error") == 0
    assert exit_code_for(report, "any") == 0
    report.summary.errors = 1
    report.summary.total_findings = 1
    assert exit_code_for(report, "error") == 1
    assert exit_code_for(report, "warning") == 1
    assert exit_code_for(report, "any") == 1
    assert exit_code_for(report, "never") == 0


def test_allow_exec_defaults_on_for_local(make_project):
    project = make_project({"app.py": "x = 1\n"})
    outcome = run_scan(ScanRequest(target=str(project)))
    assert outcome.report.exec_allowed is True


def test_no_exec_skips_code_executing_checks(make_project):
    project = make_project({
        "app.js": "console.log('hi')\n",
        "package.json": '{"name": "t", "version": "1.0.0"}\n',
    })
    outcome = run_scan(
        ScanRequest(target=str(project), analyzers=["javascript"], allow_exec=False)
    )
    assert outcome.report.exec_allowed is False
    js = next(r for r in outcome.report.results if r.analyzer == "javascript")
    assert "eslint" in js.skipped_checks
    assert "npm-audit" in js.skipped_checks


def test_no_exec_report_renders_notes(make_project):
    from repomedic.output.markdown_output import render_fix_report

    project = make_project({
        "app.js": "console.log('hi')\n",
        "package.json": '{"name": "t", "version": "1.0.0"}\n',
    })
    outcome = run_scan(
        ScanRequest(target=str(project), analyzers=["javascript"], allow_exec=False)
    )
    md = render_fix_report(outcome.report)
    assert "exec: disabled" in md
    assert "Analyzer notes" in md
    assert "eslint" in md
