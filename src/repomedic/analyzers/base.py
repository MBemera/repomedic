"""Base analyzer ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult


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
