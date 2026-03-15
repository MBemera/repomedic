"""Tests for the rich output formatter."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from repomedic.models import (
    AnalyzerResult,
    Category,
    Finding,
    ScanReport,
    Severity,
)
from repomedic.output.rich_output import _group_findings, _score_badge, print_rich


def test_score_badge_a():
    badge = _score_badge(95, "A")
    assert "95/100" in badge
    assert "Grade: A" in badge


def test_score_badge_f():
    badge = _score_badge(20, "F")
    assert "20/100" in badge
    assert "Grade: F" in badge


def test_group_findings():
    findings = [
        Finding(category=Category.static_analysis, severity=Severity.error, code="E1", title="err", description="d"),
        Finding(category=Category.static_analysis, severity=Severity.warning, code="W1", title="warn", description="d"),
        Finding(category=Category.static_analysis, severity=Severity.info, code="I1", title="info", description="d"),
    ]
    fix_now, should_fix, nice = _group_findings(findings)
    assert len(fix_now) == 1
    assert len(should_fix) == 1
    assert len(nice) == 1


def test_print_rich_no_findings():
    report = ScanReport(target="/tmp/test")
    report.build_summary()
    buf = StringIO()
    console = Console(file=buf, force_terminal=True)
    print_rich(report, console)
    output = buf.getvalue()
    assert "healthy" in output.lower() or "No issues" in output


def test_print_rich_with_findings():
    report = ScanReport(target="/tmp/test", results=[
        AnalyzerResult(analyzer="test", findings=[
            Finding(category=Category.static_analysis, severity=Severity.error, code="T1", title="Test error", description="desc", suggestion="Fix it"),
        ]),
    ])
    report.build_summary()
    buf = StringIO()
    console = Console(file=buf, force_terminal=True)
    print_rich(report, console)
    output = buf.getvalue()
    assert "Fix Now" in output or "BROKEN" in output or "T1" in output
