"""Tests for the markdown agent-handoff report."""

from __future__ import annotations

from pathlib import Path

from repomedic.models import (
    AnalyzerResult,
    Category,
    Finding,
    ScanReport,
    Severity,
)
from repomedic.output.markdown_output import generate_fix_report, render_fix_report


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


def test_front_matter_fields(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="TEST-001",
            title="Broken thing",
            description="Something is broken.",
            file_path="src/app.py",
            line=42,
        ),
    ]
    report = _make_report(findings)
    content = render_fix_report(report)

    assert content.startswith("---\n")
    assert "tool: repomedic" in content
    assert "schema: 2" in content
    assert "errors: 1" in content
    assert "shown: 1" in content
    assert "target: /tmp/test-project" in content


def test_findings_grouped_by_file(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.warning,
            code="W-001",
            title="Warning in b",
            description="warn",
            file_path="b.py",
            line=1,
        ),
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="E-001",
            title="Error in a",
            description="err",
            file_path="a.py",
            line=3,
        ),
        Finding(
            category=Category.git_health,
            severity=Severity.warning,
            code="GIT-001",
            title="Uncommitted changes",
            description="dirty tree",
        ),
    ]
    report = _make_report(findings)
    content = render_fix_report(report)

    # Files with errors come before files with only warnings; project-level last
    a_pos = content.index("### `a.py`")
    b_pos = content.index("### `b.py`")
    proj_pos = content.index("### (project-level)")
    assert a_pos < b_pos < proj_pos
    assert "— 1 error" in content
    assert "— 1 warning" in content


def test_finding_block_contents(tmp_path):
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
    content = render_fix_report(report)

    finding = findings[0]
    assert finding.fingerprint in content  # stable ID present
    assert "`TEST-001` error — Broken thing (line 42)" in content
    assert "`[python]`" in content
    assert "**Fix:** Fix the broken thing." in content


def test_snippets_included_and_marked(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("line1 = 1\nline2 = 2\nbroken(\nline4 = 4\nline5 = 5\n")

    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="E-001",
            title="Syntax error",
            description="bad",
            file_path="src/app.py",
            line=3,
        ),
    ]
    report = _make_report(findings, target=str(tmp_path))
    content = render_fix_report(report)

    assert "```python" in content
    assert "> 3 | broken(" in content
    assert "  2 | line2 = 2" in content

    # And snippets can be disabled
    content_no_snippets = render_fix_report(report, include_snippets=False)
    assert "```python" not in content_no_snippets


def test_omitted_findings_note(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="E-001",
            title="Error",
            description="err",
        ),
    ]
    report = _make_report(findings)
    report.summary.omitted_findings = 7
    content = render_fix_report(report)

    assert "7 lower-severity finding(s) omitted" in content
    assert "--max-findings 0" in content


def test_analyzer_failures_section(tmp_path):
    report = ScanReport(
        target="/tmp/x",
        results=[AnalyzerResult(analyzer="broken", error="RuntimeError: boom")],
    )
    report.build_summary()
    content = render_fix_report(report)

    assert "## Analyzer failures" in content
    assert "**broken**: RuntimeError: boom" in content


def test_verify_section_lists_language_commands(tmp_path):
    findings = [
        Finding(
            category=Category.static_analysis,
            severity=Severity.error,
            code="E-001",
            title="Error",
            description="err",
        ),
    ]
    report = _make_report(findings)
    report.languages = {"python": 10, "go": 2}
    content = render_fix_report(report)

    assert "## Verify after fixing" in content
    assert "repomedic sniff /tmp/test-project --fail-on error" in content
    assert "ruff check ." in content
    assert "go vet ./..." in content


def test_default_output_path():
    report = _make_report([], target="/tmp/test-project-out")
    result = generate_fix_report(report)

    assert result == Path("/tmp/test-project-out/repomedic-fixes.md")
    assert result.is_file()
    # Cleanup
    result.unlink(missing_ok=True)


def test_summary_counts(tmp_path):
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
    content = render_fix_report(report)

    assert "| error | 1 |" in content
    assert "| warning | 1 |" in content
