"""Markdown output — the agent handoff report.

This is the primary interface between repomedic and coding agents. The format
is optimized for LLM consumption:

- YAML front matter carries machine-readable summary fields.
- Findings are grouped by file so an agent can fix one file at a time.
- Every finding has a stable fingerprint (``RM-xxxxxxxx``) for cross-run
  reference, plus a code snippet so the agent often needs zero extra reads.
- A "Verify after fixing" section lists concrete re-check commands.
"""

from __future__ import annotations

from pathlib import Path

from repomedic.core.languages import fence_for_path, verify_commands_for
from repomedic.models import SEVERITY_ORDER, Finding, ScanReport

SNIPPET_CONTEXT_LINES = 2
SNIPPET_MAX_LINE_CHARS = 200

PROJECT_LEVEL = "(project-level)"

AGENT_INSTRUCTIONS = (
    "**Instructions for the coding agent:** Work through the findings below, errors first. "
    "Findings are grouped by file so you can fix one file at a time; snippets show the "
    "offending code so you usually don't need to read the whole file. Reference findings "
    "by their stable ID (`RM-…`). When done, run the commands under *Verify after fixing*."
)


def render_fix_report(report: ScanReport, include_snippets: bool = True) -> str:
    """Render the agent handoff report as a markdown string."""
    s = report.summary
    lines: list[str] = []

    # --- YAML front matter: machine-readable summary ---
    langs = ", ".join(f"{name} ({count})" for name, count in report.languages.items()) or "none detected"
    lines += [
        "---",
        "tool: repomedic",
        f"schema: {report.schema_version}",
        f"generated: {report.timestamp}",
        f"target: {report.target}",
        f"health: {s.health_score}/100 ({s.health_grade})",
        f"errors: {s.errors}",
        f"warnings: {s.warnings}",
        f"infos: {s.infos}",
        f"shown: {len(report.findings)}",
        f"omitted: {s.omitted_findings}",
        f"languages: {langs}",
        "---",
        "",
        "# RepoMedic Fix Report",
        "",
    ]

    if not report.findings and not s.omitted_findings:
        lines += ["✅ **No issues found — the project is healthy.**", ""]
        _append_analyzer_failures(lines, report)
        _append_footer(lines, report)
        return "\n".join(lines)

    lines += [AGENT_INSTRUCTIONS, ""]

    # --- Summary ---
    lines += [
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| error | {s.errors} |",
        f"| warning | {s.warnings} |",
        f"| info | {s.infos} |",
        "",
        f"Health **{s.health_score}/100 ({s.health_grade})** — "
        f"{report.files_scanned} files scanned in {report.duration_seconds}s.",
        "",
    ]

    # --- Findings grouped by file ---
    lines += ["## Findings by File", ""]
    target_root = Path(report.target)
    for file_key, findings in _group_by_file(report.findings):
        counts = _severity_counts(findings)
        heading = file_key if file_key == PROJECT_LEVEL else f"`{file_key}`"
        lines += [f"### {heading} — {counts}", ""]
        for finding in findings:
            _append_finding(lines, finding, target_root, include_snippets)

    if s.omitted_findings:
        lines += [
            f"> ⚠️ {s.omitted_findings} lower-severity finding(s) omitted to keep this report small. "
            "Re-run with `--max-findings 0` to see everything.",
            "",
        ]

    _append_analyzer_failures(lines, report)

    # --- Verification ---
    lines += ["## Verify after fixing", ""]
    lines.append(f"- `repomedic sniff {report.target} --fail-on error` — must exit 0")
    for cmd in verify_commands_for(list(report.languages)):
        lines.append(f"- `{cmd}`")
    lines.append("")

    _append_footer(lines, report)
    return "\n".join(lines)


def generate_fix_report(
    report: ScanReport,
    output_path: Path | None = None,
    include_snippets: bool = True,
) -> Path:
    """Write the agent handoff report to a file and return its path.

    Defaults to ``<target>/repomedic-fixes.md``.
    """
    if output_path is None:
        output_path = Path(report.target) / "repomedic-fixes.md"

    content = render_fix_report(report, include_snippets=include_snippets)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content + "\n", encoding="utf-8")
    return output_path


def _group_by_file(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group findings by file, most severe files first; project-level last."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.file_path or PROJECT_LEVEL, []).append(f)

    for file_findings in groups.values():
        file_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 2), f.line or 0))

    def group_key(item: tuple[str, list[Finding]]) -> tuple[int, int, str]:
        file_key, file_findings = item
        best = min(SEVERITY_ORDER.get(f.severity.value, 2) for f in file_findings)
        return (1 if file_key == PROJECT_LEVEL else 0, best, file_key)

    return sorted(groups.items(), key=group_key)


def _severity_counts(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [
        f"{counts[sev]} {sev}{'s' if counts[sev] != 1 else ''}"
        for sev in ("error", "warning", "info")
        if sev in counts
    ]
    return ", ".join(parts)


def _append_finding(
    lines: list[str], finding: Finding, target_root: Path, include_snippets: bool
) -> None:
    location = f" (line {finding.line})" if finding.line else ""
    lang_tag = f" `[{finding.language}]`" if finding.language else ""
    lines.append(
        f"#### {finding.fingerprint} `{finding.code}` {finding.severity.value}"
        f" — {finding.title}{location}{lang_tag}"
    )
    lines.append("")
    lines.append(finding.description)
    lines.append("")
    if finding.suggestion:
        lines.append(f"**Fix:** {finding.suggestion}")
        lines.append("")
    if include_snippets:
        snippet = _snippet_for(finding, target_root)
        if snippet:
            lines.append(snippet)
            lines.append("")


def _snippet_for(finding: Finding, target_root: Path) -> str | None:
    """Return a fenced snippet around the finding's line, or None."""
    if not finding.file_path or not finding.line:
        return None
    path = target_root / finding.file_path
    try:
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            return None
        file_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(file_lines):
        return None

    start = max(0, line_idx - SNIPPET_CONTEXT_LINES)
    end = min(len(file_lines), line_idx + SNIPPET_CONTEXT_LINES + 1)
    width = len(str(end))

    rows = []
    for i in range(start, end):
        marker = ">" if i == line_idx else " "
        text = file_lines[i][:SNIPPET_MAX_LINE_CHARS]
        rows.append(f"{marker} {i + 1:>{width}} | {text}")

    fence = fence_for_path(path)
    return f"```{fence}\n" + "\n".join(rows) + "\n```"


def _append_analyzer_failures(lines: list[str], report: ScanReport) -> None:
    failed = [r for r in report.results if r.error]
    if not failed:
        return
    lines += ["## Analyzer failures", ""]
    for r in failed:
        lines.append(f"- **{r.analyzer}**: {r.error}")
    lines += [
        "",
        "These analyzers crashed or could not run; their findings are missing from this report.",
        "",
    ]


def _append_footer(lines: list[str], report: ScanReport) -> None:
    lines += [
        "---",
        "",
        f"*Generated by repomedic. Re-run: `repomedic sniff {report.target}`*",
    ]
