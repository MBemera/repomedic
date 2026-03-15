"""Tests for the Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path

from repomedic.core.scanner import Scanner
from repomedic.models import ScanReport, Severity


def test_scan_returns_report(fixtures_dir):
    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), skip_tests=False)

    assert isinstance(report, ScanReport)
    assert report.target == str(fixtures_dir / "broken_imports")
    assert len(report.results) > 0


def test_scan_filter_by_analyzer(fixtures_dir):
    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), analyzer_names=["static"], skip_tests=False)

    assert len(report.results) == 1
    assert report.results[0].analyzer == "static"


def test_scan_filter_by_severity(fixtures_dir):
    scanner = Scanner()
    # "static" analyzer triggers both ERR (syntax) and WARN (unused import) in the fixtures
    report = scanner.scan(str(fixtures_dir / "broken_imports"), analyzer_names=["static"], min_severity="error", skip_tests=False)

    # Only error findings should remain
    for result in report.results:
        for finding in result.findings:
            assert finding.severity == Severity.error


def test_scan_fixture_broken_imports(fixtures_dir):
    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), skip_tests=False)

    assert report.summary.total_findings > 0
    assert report.summary.errors > 0


def test_scan_json_roundtrip(fixtures_dir):
    """Ensure report serializes to valid JSON and back."""
    import json

    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), skip_tests=False)
    data = json.loads(report.model_dump_json())

    assert "summary" in data
    assert "results" in data
    assert isinstance(data["results"], list)
