"""Base analyzer ABC and shared tool-output helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Severity

# One place mapping each external tool's severity vocabulary onto ours.
# Keys are lowercased; ESLint reports numeric severities (2=error, 1=warn).
TOOL_SEVERITY: dict[str, dict[str, Severity]] = {
    "bandit": {"high": Severity.error, "medium": Severity.warning, "low": Severity.info},
    "semgrep": {"error": Severity.error, "warning": Severity.warning, "info": Severity.info},
    "eslint": {"2": Severity.error, "1": Severity.warning},
    "npm_audit": {
        "critical": Severity.error,
        "high": Severity.error,
        "moderate": Severity.warning,
        "low": Severity.info,
        "info": Severity.info,
    },
    "shellcheck": {
        "error": Severity.error,
        "warning": Severity.warning,
        "info": Severity.info,
        "style": Severity.info,
    },
}


def map_severity(tool: str, raw: str | int | None, default: Severity = Severity.warning) -> Severity:
    """Map a tool's own severity label onto repomedic's Severity."""
    return TOOL_SEVERITY.get(tool, {}).get(str(raw).strip().lower(), default)


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        """Run analysis and return results."""
        ...

    def is_applicable(self, ctx: ScanContext) -> bool:
        """Return True if this analyzer should run on the given context."""
        return True

    def _rel(self, path: Path, ctx: ScanContext) -> str:
        """Return path relative to ctx.target, or str(path) if not possible."""
        try:
            return str(path.relative_to(ctx.target))
        except ValueError:
            return str(path)
