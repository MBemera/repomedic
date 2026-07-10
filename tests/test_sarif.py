"""Tests for the SARIF 2.1.0 output formatter."""

from __future__ import annotations

import json

from repomedic.models import AnalyzerResult, Category, Finding, ScanReport, Severity
from repomedic.output.sarif_output import FINGERPRINT_KEY, print_sarif, to_sarif


def _finding(**overrides) -> Finding:
    defaults = dict(
        category=Category.static_analysis,
        severity=Severity.error,
        code="STATIC-001",
        title="Syntax error",
        description="Unclosed parenthesis",
        file_path="src/app.py",
        line=12,
        column=5,
        suggestion="Close the parenthesis",
        fingerprint="RM-abc1234567",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _report(results: list[AnalyzerResult]) -> ScanReport:
    report = ScanReport(target="/tmp/project", results=results)
    report.build_summary()
    return report


def test_sarif_top_level_shape():
    report = _report([AnalyzerResult(analyzer="static", findings=[_finding()])])
    sarif = to_sarif(report)

    assert sarif["version"] == "2.1.0"
    assert "sarif-schema-2.1.0" in sarif["$schema"]
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "RepoMedic"
    assert driver["semanticVersion"]


def test_sarif_one_rule_per_unique_code():
    findings = [
        _finding(code="STATIC-001", line=1),
        _finding(code="STATIC-001", line=9),
        _finding(code="SEC-002", severity=Severity.warning, category=Category.security, line=3),
    ]
    report = _report([AnalyzerResult(analyzer="static", findings=findings)])
    run = to_sarif(report)["runs"][0]

    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["STATIC-001", "SEC-002"]

    for result in run["results"]:
        rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
        assert rule["id"] == result["ruleId"]


def test_sarif_severity_maps_to_level():
    findings = [
        _finding(severity=Severity.error),
        _finding(code="X-1", severity=Severity.warning),
        _finding(code="X-2", severity=Severity.info),
    ]
    report = _report([AnalyzerResult(analyzer="static", findings=findings)])
    levels = [r["level"] for r in to_sarif(report)["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_sarif_message_combines_description_and_fix():
    report = _report([AnalyzerResult(analyzer="static", findings=[_finding()])])
    message = to_sarif(report)["runs"][0]["results"][0]["message"]["text"]
    assert "Unclosed parenthesis" in message
    assert "Fix: Close the parenthesis" in message


def test_sarif_location_is_relative_posix_with_region():
    report = _report([AnalyzerResult(analyzer="static", findings=[_finding()])])
    location = to_sarif(report)["runs"][0]["results"][0]["locations"][0]
    physical = location["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/app.py"
    assert physical["region"] == {"startLine": 12, "startColumn": 5}


def test_sarif_project_level_finding_has_no_location():
    finding = _finding(file_path=None, line=None, column=None)
    report = _report([AnalyzerResult(analyzer="git", findings=[finding])])
    result = to_sarif(report)["runs"][0]["results"][0]
    assert "locations" not in result


def test_sarif_partial_fingerprints_carry_v2_id():
    report = _report([AnalyzerResult(analyzer="static", findings=[_finding()])])
    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {FINGERPRINT_KEY: "RM-abc1234567"}


def test_sarif_invocation_carries_failures_and_skipped_checks():
    results = [
        AnalyzerResult(analyzer="rust", error="Timed out after 120s"),
        AnalyzerResult(analyzer="golang", skipped_checks=["go build (exec disabled)"]),
    ]
    report = _report(results)
    invocation = to_sarif(report)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is True
    notifications = invocation["toolExecutionNotifications"]
    texts = [n["message"]["text"] for n in notifications]
    levels = [n["level"] for n in notifications]
    assert any("rust" in t and "Timed out" in t for t in texts)
    assert any("golang" in t and "go build" in t for t in texts)
    assert "error" in levels and "note" in levels


def test_print_sarif_is_valid_json():
    report = _report([AnalyzerResult(analyzer="static", findings=[_finding()])])
    parsed = json.loads(print_sarif(report))
    assert parsed["runs"][0]["results"]


def test_cli_scan_output_sarif(make_project):
    from typer.testing import CliRunner

    from repomedic.cli import app

    project = make_project({"app.py": "import os\nprint(os.name)\n"})
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(project), "--output", "sarif"])

    assert result.exit_code in (0, 1)
    parsed = json.loads(result.stdout)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "RepoMedic"
