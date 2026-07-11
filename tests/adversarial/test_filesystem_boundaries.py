"""Containment and bounded-file adversarial tests."""

from __future__ import annotations

import os
import time

import pytest

from repomedic.core.service import ScanRequest, run_scan
from repomedic.models import AnalyzerResult, Category, Finding, ScanReport, Severity
from repomedic.output.json_output import print_json
from repomedic.output.markdown_output import render_fix_report
from repomedic.output.sarif_output import print_sarif
from tests.adversarial.payloads import BINARY_CANARY, SYMLINK_ESCAPE_CANARY

pytestmark = pytest.mark.adversarial

TEN_MEBIBYTES = 10 * 1024 * 1024
SCAN_BUDGET_SECONDS = 5.0


def test_symlink_escape_is_excluded_and_never_read(make_project) -> None:
    workspace = make_project({"project/app.py": "value = 1\n"})
    project = workspace / "project"
    external_file = workspace / "external-private.log"
    external_file.write_text(SYMLINK_ESCAPE_CANARY, encoding="utf-8")
    os.symlink(external_file, project / "escape.log")

    report = run_scan(
        ScanRequest(
            target=str(project),
            analyzers=["logs", "hygiene"],
            allow_exec=False,
        )
    ).report
    report.results.append(
        AnalyzerResult(
            analyzer="untrusted-tool",
            findings=[
                Finding(
                    category=Category.log_analysis,
                    severity=Severity.error,
                    code="ADV-SYMLINK",
                    title="External-looking finding",
                    description="The path came from an untrusted analyzer.",
                    file_path="escape.log",
                    line=1,
                )
            ],
        )
    )
    report.build_summary()

    assert report.files_scanned == 1
    serialized_outputs = (
        print_json(report),
        render_fix_report(report, include_snippets=True),
        print_sarif(report),
    )
    assert all(SYMLINK_ESCAPE_CANARY not in output for output in serialized_outputs)


def test_ten_mebibyte_file_completes_within_budget_without_snippet(
    make_project,
) -> None:
    project = make_project({"app.py": "value = 1\n"})
    huge_file = project / "huge-artifact.bin"
    with huge_file.open("wb") as output:
        output.write(b"HUGE-SNIPPET-CANARY\n")
        output.seek(TEN_MEBIBYTES - 1)
        output.write(b"\0")

    started = time.monotonic()
    report = run_scan(
        ScanRequest(
            target=str(project),
            analyzers=["hygiene"],
            allow_exec=False,
            analyzer_timeout=2,
        )
    ).report
    elapsed = time.monotonic() - started
    markdown = render_fix_report(report, include_snippets=True)

    assert elapsed < SCAN_BUDGET_SECONDS
    assert any(
        finding.code == "HYG-001" and finding.file_path == huge_file.name
        for finding in report.findings
    )
    assert "HUGE-SNIPPET-CANARY" not in markdown


def test_binary_file_content_is_never_rendered_as_a_snippet(make_project) -> None:
    project = make_project({"app.py": "value = 1\n"})
    binary_file = project / "capture.bin"
    binary_file.write_bytes(
        (b"a\n" * 4097) + b"\x00\n" + BINARY_CANARY + b"\n"
    )
    finding = Finding(
        category=Category.static_analysis,
        severity=Severity.error,
        code="ADV-BINARY",
        title="Binary parser finding",
        description="An untrusted parser reported a location in a binary file.",
        file_path=binary_file.name,
        line=4099,
    )
    report = ScanReport(
        target=str(project),
        results=[AnalyzerResult(analyzer="untrusted-tool", findings=[finding])],
    )
    report.build_summary()

    markdown = render_fix_report(report, include_snippets=True).encode()

    assert BINARY_CANARY not in markdown


def test_terminal_control_file_is_never_rendered_as_a_snippet(make_project) -> None:
    project = make_project({"app.py": "value = 1\n"})
    control_file = project / "control.txt"
    control_file.write_bytes(
        b"safe\n\x1b]52;c;VEVSTUlOQUwtQ09OVFJPTC1DQU5BUlk=\x07\n"
        + "\u009b31m".encode()
        + BINARY_CANARY
        + b"\n"
    )
    finding = Finding(
        category=Category.static_analysis,
        severity=Severity.error,
        code="ADV-CONTROL",
        title="Terminal control finding",
        description="An untrusted parser reported terminal-active content.",
        file_path=control_file.name,
        line=3,
    )
    report = ScanReport(
        target=str(project),
        results=[AnalyzerResult(analyzer="untrusted-tool", findings=[finding])],
    )
    report.build_summary()

    markdown = render_fix_report(report, include_snippets=True).encode()

    assert BINARY_CANARY not in markdown
    assert b"\x1b" not in markdown
    assert b"\x07" not in markdown
