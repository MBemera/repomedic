"""repomedic — AI-agent repo debugging system."""

from repomedic.core.scanner import Scanner
from repomedic.models import ScanReport


def scan(path: str = ".", analyzers: list[str] | None = None) -> ScanReport:
    """Convenience function: scan a directory and return a structured report."""
    scanner = Scanner()
    return scanner.scan(path, analyzer_names=analyzers)


__all__ = ["scan", "Scanner", "ScanReport"]
