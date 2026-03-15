"""JSON output formatter."""

from __future__ import annotations

from repomedic.models import ScanReport


def print_json(report: ScanReport) -> str:
    """Serialize report to JSON string."""
    return report.model_dump_json(indent=2)
