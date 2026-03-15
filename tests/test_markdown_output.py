"""Tests for the markdown output formatter."""

from __future__ import annotations

from pathlib import Path

from repomedic.models import (
    AnalyzerResult,
    Category,
    Finding,
    ScanReport,
    Severity,
)
from repomedic.output.markdown_output import generate_fix_report


def _make_report(findings: list[Finding], target: str = "/tmp/test-project") -> ScanReport:
    """Helper to create a ScanReport from findings."""
    result = AnalyzerResult(analyzer="test", findings=findings)
    report = ScanReport(target=target, results=[result])
    report.build_summary()
    return report


def test_empty_report(tmp_path):
    report = _make_report([])
    out = tmp_path / "fixes.md"
    result = generate_fix_report(report, out)

    assert result == out
    content = out.read_text()
    assert "No issues found" in content
    assert "Fix Report" in content


def test_report_with_errors(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="TEST-001",
            title="Broken thing",
            description="Something is broken.",
            file_path="src/app.py",
            line=42,
            suggestion="Fix the broken thing.",
            language="python",
        ),
    ]
    report = _make_report(findings)
    out = tmp_path / "fixes.md"
    generate_fix_report(report, out)

    content = out.read_text()
    assert "Critical Fixes" in content
    assert "TEST-001" in content
    assert "Broken thing" in content
    assert "src/app.py:42" in content
    assert "Fix the broken thing" in content
    assert "[python]" in content


def test_report_with_mixed_severities(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="ERR-001",
            title="Error finding",
            description="An error.",
            suggestion="Fix it.",
        ),
        Finding(
            category=Category.static_analysis,
            severity=Severity.warning,
            code="WARN-001",
            title="Warning finding",
            description="A warning.",
            suggestion="Check it.",
        ),
        Finding(
            category=Category.static_analysis,
            severity=Severity.info,
            code="INFO-001",
            title="Info finding",
            description="A tip.",
            suggestion="Consider it.",
        ),
    ]
    report = _make_report(findings)
    out = tmp_path / "fixes.md"
    generate_fix_report(report, out)

    content = out.read_text()
    assert "Critical Fixes" in content
    assert "Warnings" in content
    assert "Suggestions" in content
    assert "ERR-001" in content
    assert "WARN-001" in content
    assert "INFO-001" in content


def test_report_summary_table(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="E-001",
            title="Error",
            description="err",
        ),
        Finding(
            category=Category.static_analysis,
            severity=Severity.warning,
            code="W-001",
            title="Warning",
            description="warn",
        ),
    ]
    report = _make_report(findings)
    out = tmp_path / "fixes.md"
    generate_fix_report(report, out)

    content = out.read_text()
    # Summary table should have correct counts
    assert "| 🔴 Errors | 1 |" in content
    assert "| 🟡 Warnings | 1 |" in content


def test_default_output_path():
    report = _make_report([], target="/tmp/test-project-out")
    result = generate_fix_report(report)

    assert result == Path("/tmp/test-project-out/repomedic-fixes.md")
    assert result.is_file()
    # Cleanup
    result.unlink(missing_ok=True)


def test_footer_present(tmp_path):
    report = _make_report([])
    out = tmp_path / "fixes.md"
    generate_fix_report(report, out)

    content = out.read_text()
    assert "Feed this file to your coding agent" in content


def test_language_tags_in_report(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="JS-001",
            title="JS error",
            description="Broken JS.",
            language="javascript",
        ),
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="GO-001",
            title="Go error",
            description="Broken Go.",
            language="go",
        ),
        Finding(
            category=Category.static_analysis,
            severity=Severity.warning,
            code="GIT-001",
            title="Git warning",
            description="Uncommitted changes.",
            language=None,
        ),
    ]
    report = _make_report(findings)
    out = tmp_path / "fixes.md"
    generate_fix_report(report, out)

    content = out.read_text()
    assert "[javascript]" in content
    assert "[go]" in content
    # Language-agnostic finding should NOT have a tag
    assert "GIT-001 — Git warning\n" in content  # no language tag
