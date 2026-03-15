"""Markdown output formatter — generates agent-consumable fix reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from repomedic.models import Finding, ScanReport, Severity


def generate_fix_report(report: ScanReport, output_path: Path | None = None) -> Path:
    """Generate a structured markdown fix report for consumption by coding agents.

    Args:
        report: The scan report to format.
        output_path: Where to write the markdown file. Defaults to
                     ``<target>/repomedic-fixes.md``.

    Returns:
        The path to the generated markdown file.
    """
    if output_path is None:
        output_path = Path(report.target) / "repomedic-fixes.md"

    lines: list[str] = []
    s = report.summary

    # Header
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("# 🔧 RepoMedic Fix Report")
    lines.append("")
    lines.append(f"> **Generated:** {timestamp} | **Target:** `{report.target}` | **Health:** {s.health_score}/100 ({s.health_grade})")
    lines.append("")

    # Quick stats
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| 🔴 Errors | {s.errors} |")
    lines.append(f"| 🟡 Warnings | {s.warnings} |")
    lines.append(f"| 🔵 Info/Tips | {s.infos} |")
    lines.append(f"| Analyzers Run | {s.analyzers_run} |")
    lines.append("")

    if not report.findings:
        lines.append("✅ **No issues found — your project is healthy!**")
        lines.append("")
        _write_footer(lines)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    # Group findings
    errors = [f for f in report.findings if f.severity == Severity.error]
    warnings = [f for f in report.findings if f.severity == Severity.warning]
    infos = [f for f in report.findings if f.severity == Severity.info]

    fix_num = 1

    if errors:
        lines.append("## 🔴 Critical Fixes (Errors)")
        lines.append("")
        for finding in errors:
            fix_num = _write_finding(lines, finding, fix_num)
        lines.append("")

    if warnings:
        lines.append("## 🟡 Warnings")
        lines.append("")
        for finding in warnings:
            fix_num = _write_finding(lines, finding, fix_num)
        lines.append("")

    if infos:
        lines.append("## 🔵 Suggestions")
        lines.append("")
        for finding in infos:
            fix_num = _write_finding(lines, finding, fix_num)
        lines.append("")

    _write_footer(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _write_finding(lines: list[str], finding: Finding, fix_num: int) -> int:
    """Append a single finding block to lines. Returns the next fix_num."""
    location = _format_location(finding)
    lang_tag = f" [{finding.language}]" if finding.language else ""

    lines.append(f"### Fix {fix_num}: {finding.code} — {finding.title}{lang_tag}")
    lines.append("")
    lines.append(f"- **File:** `{location}`")
    lines.append(f"- **Problem:** {finding.description}")
    if finding.suggestion:
        lines.append(f"- **Fix:** {finding.suggestion}")
    lines.append("")
    return fix_num + 1


def _format_location(finding: Finding) -> str:
    """Format the file location string."""
    if not finding.file_path:
        return "(project-level)"
    loc = finding.file_path
    if finding.line:
        loc += f":{finding.line}"
    if finding.column:
        loc += f":{finding.column}"
    return loc


def _write_footer(lines: list[str]) -> None:
    """Append the report footer."""
    lines.append("---")
    lines.append("")
    lines.append("*Feed this file to your coding agent. Each fix is self-contained with file, problem, and solution.*")
    lines.append("")
