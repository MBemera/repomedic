"""Tests for baseline write/load/apply and the scan-pipeline round trip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repomedic.core.baseline import (
    BASELINE_FILENAME,
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from repomedic.models import AnalyzerResult, Category, Finding, ScanReport, Severity
from tests.cli_runner import create_cli_runner


def _finding(code: str = "STATIC-001", fingerprint: str = "RM-aaaaaaaaaa") -> Finding:
    return Finding(
        category=Category.static_analysis,
        severity=Severity.error,
        code=code,
        title="Broken thing",
        description="It is broken",
        file_path="app.py",
        line=1,
        fingerprint=fingerprint,
    )


def test_write_baseline_snapshots_sorted_unique_fingerprints(tmp_path: Path):
    report = ScanReport(
        target="/tmp/x",
        results=[
            AnalyzerResult(
                analyzer="static",
                findings=[
                    _finding(fingerprint="RM-bbbbbbbbbb"),
                    _finding(fingerprint="RM-aaaaaaaaaa"),
                    _finding(fingerprint="RM-bbbbbbbbbb"),
                ],
            )
        ],
    )
    path = tmp_path / BASELINE_FILENAME
    model = write_baseline(report, path)

    assert model.fingerprints == ["RM-aaaaaaaaaa", "RM-bbbbbbbbbb"]
    on_disk = json.loads(path.read_text())
    assert on_disk["schema_version"] == 1
    assert on_disk["fingerprints"] == ["RM-aaaaaaaaaa", "RM-bbbbbbbbbb"]


def test_load_baseline_round_trip(tmp_path: Path):
    report = ScanReport(
        target="/tmp/x",
        results=[AnalyzerResult(analyzer="static", findings=[_finding()])],
    )
    path = tmp_path / BASELINE_FILENAME
    write_baseline(report, path)
    assert load_baseline(path) == {"RM-aaaaaaaaaa"}


def test_load_baseline_rejects_invalid_json(tmp_path: Path):
    path = tmp_path / BASELINE_FILENAME
    path.write_text("{not json")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_baseline_rejects_missing_file(tmp_path: Path):
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "nope.json")


def test_apply_baseline_drops_only_matching_findings():
    results = [
        AnalyzerResult(
            analyzer="static",
            findings=[_finding(fingerprint="RM-old0000000"), _finding(fingerprint="RM-new0000000")],
        )
    ]
    dropped = apply_baseline(results, {"RM-old0000000"})
    assert dropped == 1
    assert [f.fingerprint for f in results[0].findings] == ["RM-new0000000"]


def test_scan_pipeline_baseline_round_trip(make_project):
    """A baseline of the current scan suppresses everything on the next scan."""
    from repomedic.core.service import ScanRequest, run_scan
    from repomedic.core.baseline import write_baseline

    project = make_project(
        {"app.py": "import os\npassword = 'hunter2-secret-value'\n"}
    )

    first = run_scan(ScanRequest(target=str(project), max_findings=0, fail_on="any"))
    if not first.report.findings:
        pytest.skip("fixture produced no findings to baseline")

    write_baseline(first.report, project / BASELINE_FILENAME)

    second = run_scan(ScanRequest(target=str(project), max_findings=0, fail_on="any"))
    assert second.report.findings == []
    assert second.report.summary.suppressed_findings >= len(first.report.findings)
    assert second.exit_code == 0


def test_scan_no_baseline_reports_everything(make_project):
    from repomedic.core.service import ScanRequest, run_scan
    from repomedic.core.baseline import write_baseline

    project = make_project({"app.py": "import os\nx = eval(input())\n"})

    first = run_scan(ScanRequest(target=str(project), max_findings=0))
    if not first.report.findings:
        pytest.skip("fixture produced no findings to baseline")
    write_baseline(first.report, project / BASELINE_FILENAME)

    unbaselined = run_scan(
        ScanRequest(target=str(project), max_findings=0, use_baseline=False)
    )
    assert len(unbaselined.report.findings) >= len(first.report.findings)
    assert unbaselined.report.summary.suppressed_findings == 0


def test_scan_explicit_missing_baseline_is_usage_error(make_project):
    from repomedic.core.service import ScanRequest, ScanServiceError, run_scan

    project = make_project({"app.py": "print('hi')\n"})
    with pytest.raises(ScanServiceError):
        run_scan(ScanRequest(target=str(project), baseline=str(project / "missing.json")))


def test_cli_baseline_command_writes_file(make_project):
    from repomedic.cli import app

    project = make_project({"app.py": "import os\nprint(os.name)\n"})
    runner = create_cli_runner()
    result = runner.invoke(app, ["baseline", str(project)])

    assert result.exit_code == 0
    baseline_path = project / BASELINE_FILENAME
    assert baseline_path.is_file()
    assert json.loads(baseline_path.read_text())["schema_version"] == 1
