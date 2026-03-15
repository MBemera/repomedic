"""Log file analyzer — parse log files, find error patterns, group tracebacks."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity

LOG_LEVEL_RE = re.compile(
    r"\b(ERROR|CRITICAL|FATAL|WARNING|WARN|INFO|DEBUG)\b", re.IGNORECASE
)
TRACEBACK_START_RE = re.compile(r"^Traceback \(most recent call last\):", re.MULTILINE)


@register
class LogAnalyzer(BaseAnalyzer):
    name = "logs"
    description = "Parse log files, classify lines by level, group tracebacks"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.log_files) > 0

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        for log_file in ctx.log_files:
            findings.extend(self._analyze_log(log_file, ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _analyze_log(self, path: Path, ctx: ScanContext) -> list[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel = self._rel(path, ctx)
        findings: list[Finding] = []

        # Count error/warning lines
        error_lines = []
        lines = content.splitlines()
        error_counter: Counter[str] = Counter()

        for i, line in enumerate(lines, 1):
            match = LOG_LEVEL_RE.search(line)
            if match:
                level = match.group(1).upper()
                if level in ("ERROR", "CRITICAL", "FATAL"):
                    error_lines.append((i, line.strip()))
                    # Extract the error message part after the level
                    msg_part = line[match.end() :].strip().lstrip(":- ")
                    # Group by first 80 chars of message
                    error_counter[msg_part[:80]] += 1

        if error_lines:
            top_errors = error_counter.most_common(5)
            desc_parts = [f"  {count}x: {msg}" for msg, count in top_errors]
            findings.append(
                Finding(
                    category=Category.log_analysis,
                    severity=Severity.error,
                    code="LOG-001",
                    title=f"{len(error_lines)} error(s) in {path.name}",
                    description="Top error patterns:\n" + "\n".join(desc_parts),
                    file_path=rel,
                    line=error_lines[0][0],
                    suggestion="Investigate the most frequent errors listed above and fix their root causes.",
                    metadata={
                        "total_errors": len(error_lines),
                        "top_errors": dict(top_errors),
                    },
                )
            )

        # Find tracebacks
        tb_count = len(TRACEBACK_START_RE.findall(content))
        if tb_count:
            findings.append(
                Finding(
                    category=Category.log_analysis,
                    severity=Severity.error,
                    code="LOG-002",
                    title=f"{tb_count} traceback(s) in {path.name}",
                    description=f"Found {tb_count} Python traceback(s) in log file.",
                    file_path=rel,
                    suggestion="Review the tracebacks in the log file to identify and fix the exceptions.",
                )
            )

        return findings

