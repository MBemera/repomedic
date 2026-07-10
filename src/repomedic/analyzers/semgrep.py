"""Semgrep analyzer — multi-language SAST for complex security/logic bugs."""

from __future__ import annotations

import logging
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer, map_severity
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding
from repomedic.utils.process import JSON_REPORT_PLACEHOLDER, run_json_tool

logger = logging.getLogger("repomedic")


@register
class SemgrepAnalyzer(BaseAnalyzer):
    name = "semgrep"
    description = "Advanced multi-language SAST using Semgrep"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.files) > 0  # Semgrep can scan almost anything

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        data, result = run_json_tool(
            [
                "semgrep", "scan", "--json", "--quiet", "--config", "auto",
                "--output", JSON_REPORT_PLACEHOLDER, str(ctx.target),
            ],
            cwd=str(ctx.target),
            timeout=300,  # Semgrep can take a while on large repos
        )

        if not result.ran:
            # Semgrep not installed — skip quietly; `repomedic doctor` surfaces
            # optional tools, and a per-scan info finding is just noise for agents.
            return AnalyzerResult(analyzer=self.name)

        if not isinstance(data, dict):
            logger.warning("Semgrep produced no parseable JSON report")
            return AnalyzerResult(analyzer=self.name)

        for res in data.get("results", []):
            extra = res.get("extra", {})
            findings.append(
                Finding(
                    category=Category.security if "security" in res.get("check_id", "").lower() else Category.static_analysis,
                    severity=map_severity("semgrep", extra.get("severity", "WARNING")),
                    code=res.get("check_id", "SEMGREP-002"),
                    title="Semgrep finding",
                    description=extra.get("message", "Semgrep detected an issue."),
                    file_path=self._rel(Path(res.get("path", "")), ctx),
                    line=res.get("start", {}).get("line"),
                    column=res.get("start", {}).get("col"),
                    suggestion=extra.get("metadata", {}).get("source", "Review the issue corresponding to the semgrep rule."),
                )
            )

        return AnalyzerResult(analyzer=self.name, findings=findings)
