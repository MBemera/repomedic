"""Adversarial coverage for repository-controlled report text."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import pytest
import yaml

import repomedic.analyzers.dependencies as dependencies_module
import repomedic.analyzers.runtime as runtime_module
import repomedic.analyzers.security as security_module
from repomedic.analyzers.dependencies import DependencyAnalyzer
from repomedic.analyzers.hygiene import HygieneAnalyzer
from repomedic.analyzers.logs import LogAnalyzer
from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.analyzers.security import SecurityAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, ScanReport, Severity
from repomedic.output.markdown_output import render_fix_report
from repomedic.utils.process import ProcessResult, ProcessStatus
from tests.adversarial.payloads import (
    ALL_PAYLOADS,
    FENCE_ESCAPE,
    FILENAME_PAYLOAD,
    FRONT_MATTER_ESCAPE,
    PACKAGE_NAME_PAYLOAD,
    PROMPT_INJECTION,
    RICH_MARKUP,
    SYMLINK_TARGET_PAYLOAD,
    TERMINAL_CONTROL,
    longest_backtick_run,
)

pytestmark = pytest.mark.adversarial

_FENCE_OPEN = re.compile(r"^(`{3,})[A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class FenceRegion:
    content_start: int
    content_end: int
    fence_length: int


def _report_with_findings(findings: list[Finding], target: str = "/tmp/project") -> ScanReport:
    report = ScanReport(
        target=target,
        results=[AnalyzerResult(analyzer="adversarial", findings=findings)],
    )
    report.build_summary()
    return report


def _fence_regions(markdown: str) -> list[FenceRegion]:
    regions: list[FenceRegion] = []
    open_fence: tuple[str, int] | None = None
    offset = 0

    for line_with_ending in markdown.splitlines(keepends=True):
        line = line_with_ending.rstrip("\r\n")
        if open_fence is None:
            match = _FENCE_OPEN.fullmatch(line)
            if match:
                open_fence = (match.group(1), offset + len(line_with_ending))
        elif line == open_fence[0]:
            fence, content_start = open_fence
            regions.append(
                FenceRegion(
                    content_start=content_start,
                    content_end=offset,
                    fence_length=len(fence),
                )
            )
            open_fence = None
        offset += len(line_with_ending)

    assert open_fence is None, "rendered markdown contains an unclosed fence"
    return regions


def _assert_text_is_strictly_fenced(markdown: str, text: str) -> None:
    regions = _fence_regions(markdown)
    expected_fence_length = longest_backtick_run(text)
    occurrences = [match.span() for match in re.finditer(re.escape(text), markdown)]
    assert occurrences, f"expected payload was not rendered: {text[:40]!r}"

    for start, end in occurrences:
        containing_region = next(
            (
                region
                for region in regions
                if region.content_start <= start and end <= region.content_end
            ),
            None,
        )
        assert containing_region is not None, "raw payload escaped its fenced block"
        assert containing_region.fence_length > expected_fence_length


def _outside_fence_headings(markdown: str) -> list[str]:
    regions = _fence_regions(markdown)
    headings: list[str] = []
    offset = 0
    for line_with_ending in markdown.splitlines(keepends=True):
        line = line_with_ending.rstrip("\r\n")
        is_fenced = any(
            region.content_start <= offset < region.content_end for region in regions
        )
        if not is_fenced and re.match(r"^#{1,6}\s", line):
            headings.append(line)
        offset += len(line_with_ending)
    return headings


def _heading_with_marker(headings: list[str], marker: str) -> str:
    matching_headings = [heading for heading in headings if marker in heading]
    assert len(matching_headings) == 1, f"expected one heading for {marker}"
    return matching_headings[0]


def test_all_payloads_are_quarantined_and_never_raw_in_headings() -> None:
    findings = [
        Finding(
            category=Category.log_analysis,
            severity=Severity.error,
            code=f"ADV-{index:03d}",
            title=payload.text,
            description=payload.text,
        )
        for index, payload in enumerate(ALL_PAYLOADS, start=1)
    ]

    markdown = render_fix_report(
        _report_with_findings(findings),
        include_snippets=False,
    )

    headings = _outside_fence_headings(markdown)
    for payload in ALL_PAYLOADS:
        _assert_text_is_strictly_fenced(markdown, payload.text)
        heading = _heading_with_marker(headings, payload.marker)
        assert payload.text not in heading

    rich_heading = _heading_with_marker(headings, RICH_MARKUP.marker)
    assert "<details" not in rich_heading
    assert "<img" not in rich_heading
    assert "&lt;details" in rich_heading


def test_terminal_controls_are_visible_data_not_active_bytes() -> None:
    finding = Finding(
        category=Category.log_analysis,
        severity=Severity.error,
        code="ADV-CONTROL",
        title=TERMINAL_CONTROL.text,
        description=TERMINAL_CONTROL.text,
        suggestion=TERMINAL_CONTROL.text,
    )

    markdown = render_fix_report(
        _report_with_findings([finding]),
        include_snippets=False,
    )

    assert TERMINAL_CONTROL.marker in markdown
    assert "\x1b" not in markdown
    assert "\x07" not in markdown
    assert "\x9b" not in markdown
    assert "\\u001b" in markdown
    assert "\\u0007" in markdown
    assert "\\u009b" in markdown


def test_hostile_front_matter_target_round_trips_as_data() -> None:
    target = f"/tmp/project\n{FRONT_MATTER_ESCAPE.text}"
    markdown = render_fix_report(_report_with_findings([], target=target))
    lines = markdown.splitlines()
    closing_index = lines.index("---", 1)

    front_matter = yaml.safe_load("\n".join(lines[1:closing_index]))

    assert front_matter["tool"] == "repomedic"
    assert front_matter["target"] == target
    assert front_matter["errors"] == 0


def test_real_analyzer_sinks_keep_repository_payloads_as_data(
    make_project,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    todo_lines = "\n".join(
        f"# TODO {PROMPT_INJECTION.text}" for _ in range(12)
    )
    project = make_project(
        {
            FILENAME_PAYLOAD: todo_lines + "\n",
            "events.log": f"ERROR {RICH_MARKUP.text}\n",
            ".env": f"VALUE={FRONT_MATTER_ESCAPE.text}\n",
            "run.sh": f"# simulated stderr payload\n{FENCE_ESCAPE.text}\n",
            "requirements.txt": f"{PACKAGE_NAME_PAYLOAD}\n",
            ".venv/bin/python": "",
        }
    )
    os.symlink(SYMLINK_TARGET_PAYLOAD, project / "dangling")

    monkeypatch.setattr(
        dependencies_module,
        "run",
        lambda *args, **kwargs: ProcessResult(
            ProcessStatus.ok,
            0,
            "[]",
            "",
        ),
    )
    monkeypatch.setattr(
        runtime_module,
        "run",
        lambda *args, **kwargs: ProcessResult(
            ProcessStatus.ok,
            7,
            "",
            FENCE_ESCAPE.text,
        ),
    )
    monkeypatch.setattr(
        security_module,
        "run_json_tool",
        lambda *args, **kwargs: (
            None,
            ProcessResult(ProcessStatus.not_found, None, "", "gitleaks unavailable"),
        ),
    )

    context = ScanContext(project, skip_tests=False)
    results = [
        LogAnalyzer().analyze(context),
        HygieneAnalyzer().analyze(context),
        SecurityAnalyzer().analyze(context),
        DependencyAnalyzer().analyze(context),
        RuntimeAnalyzer().analyze_script(str(project / "run.sh"), cwd=str(project)),
    ]
    report = ScanReport(target=str(project), results=results)
    report.build_summary()

    markdown = render_fix_report(report, include_snippets=True)

    _assert_text_is_strictly_fenced(markdown, FILENAME_PAYLOAD)
    _assert_text_is_strictly_fenced(markdown, FENCE_ESCAPE.text)
    _assert_text_is_strictly_fenced(markdown, PACKAGE_NAME_PAYLOAD)
    _assert_text_is_strictly_fenced(markdown, SYMLINK_TARGET_PAYLOAD)
    assert FRONT_MATTER_ESCAPE.text not in markdown

    headings = _outside_fence_headings(markdown)
    raw_heading_payloads = (
        FILENAME_PAYLOAD,
        FENCE_ESCAPE.text,
        PACKAGE_NAME_PAYLOAD,
        SYMLINK_TARGET_PAYLOAD,
    )
    assert all(
        payload not in heading
        for payload in raw_heading_payloads
        for heading in headings
    )
