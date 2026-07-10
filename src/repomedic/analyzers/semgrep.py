"""Semgrep analyzer — multi-language SAST for complex security/logic bugs."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run

logger = logging.getLogger("repomedic")


@register
class SemgrepAnalyzer(BaseAnalyzer):
    name = "semgrep"
    description = "Advanced multi-language SAST using Semgrep"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.files) > 0  # Semgrep can scan almost anything

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        # Run semgrep: semgrep scan --json --quiet --config auto --output <file> <dir>
        result = run(
            ["semgrep", "scan", "--json", "--quiet", "--config", "auto", "--output", report_path, str(ctx.target)],
            cwd=str(ctx.target),
            timeout=300, # Semgrep can take a while on large repos
        )

        if not result.ran:
            # Semgrep not installed — skip quietly; `repomedic doctor` surfaces
            # optional tools, and a per-scan info finding is just noise for agents.
            Path(report_path).unlink(missing_ok=True)
            return AnalyzerResult(analyzer=self.name)

        try:
            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)
            
            for res in data.get("results", []):
                extra = res.get("extra", {})
                severity_str = extra.get("severity", "WARNING").upper()
                
                if severity_str == "ERROR":
                    severity = Severity.error
                elif severity_str == "INFO":
                    severity = Severity.info
                else:
                    severity = Severity.warning

                try:
                    rel = str(Path(res["path"]).relative_to(ctx.target))
                except ValueError:
                    rel = str(res.get("path", ""))

                findings.append(
                    Finding(
                        category=Category.security if "security" in res.get("check_id", "").lower() else Category.static_analysis,
                        severity=severity,
                        code=res.get("check_id", "SEMGREP-002"),
                        title="Semgrep finding",
                        description=extra.get("message", "Semgrep detected an issue."),
                        file_path=rel,
                        line=res.get("start", {}).get("line"),
                        column=res.get("start", {}).get("col"),
                        suggestion=extra.get("metadata", {}).get("source", "Review the issue corresponding to the semgrep rule."),
                    )
                )

        except (json.JSONDecodeError, FileNotFoundError) as exc:
            logger.warning("Failed to parse semgrep report: %s", exc)
        finally:
            Path(report_path).unlink(missing_ok=True)

        return AnalyzerResult(analyzer=self.name, findings=findings)
