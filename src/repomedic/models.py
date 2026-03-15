"""Pydantic models for repomedic scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    error = "error"
    warning = "warning"
    info = "info"


class Category(str, Enum):
    static_analysis = "static_analysis"
    dependency = "dependency"
    git_health = "git_health"
    config = "config"
    runtime = "runtime"
    log_analysis = "log_analysis"
    security = "security"


class Finding(BaseModel):
    """A single diagnostic finding."""

    category: Category
    severity: Severity
    code: str = Field(description="Flat code like STATIC-001, GIT-002")
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None
    column: int | None = None
    suggestion: str = Field(
        default="",
        description="Actionable fix suggestion — primary value for AI agents",
    )
    language: str | None = Field(
        default=None,
        description="Programming language this finding relates to (python, javascript, go, rust, or None for language-agnostic)",
    )
    metadata: dict = Field(default_factory=dict)


class AnalyzerResult(BaseModel):
    """Result from a single analyzer run."""

    analyzer: str
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    elapsed_seconds: float = 0.0


class ReportSummary(BaseModel):
    """Summary counts for a scan report."""

    total_findings: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    analyzers_run: int = 0
    analyzers_failed: int = 0
    health_score: int = 100
    health_grade: str = "A"


class ScanReport(BaseModel):
    """Top-level scan report — the main output of repomedic."""

    target: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    summary: ReportSummary = Field(default_factory=ReportSummary)
    results: list[AnalyzerResult] = Field(default_factory=list)
    doctor_results: dict | None = Field(default=None, exclude=True)
    explain_results: dict | None = Field(default=None, exclude=True)

    @property
    def findings(self) -> list[Finding]:
        """Flatten all findings from all analyzers."""
        return [f for r in self.results for f in r.findings]

    def build_summary(self) -> None:
        """Recompute summary from results."""
        all_findings = self.findings
        errors = sum(1 for f in all_findings if f.severity == Severity.error)
        warnings = sum(1 for f in all_findings if f.severity == Severity.warning)
        infos = sum(1 for f in all_findings if f.severity == Severity.info)
        score, grade = _compute_score(errors, warnings, infos)
        self.summary = ReportSummary(
            total_findings=len(all_findings),
            errors=errors,
            warnings=warnings,
            infos=infos,
            analyzers_run=len(self.results),
            analyzers_failed=sum(1 for r in self.results if r.error),
            health_score=score,
            health_grade=grade,
        )


def _compute_score(errors: int, warnings: int, infos: int) -> tuple[int, str]:
    """Compute health score (0-100) and letter grade (A-F)."""
    score = max(0, 100 - errors * 15 - warnings * 5 - infos * 1)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return score, grade
