"""Baseline files: accept a repo's current findings, alert only on new ones.

``repomedic baseline`` snapshots every current fingerprint into
``.repomedic-baseline.json``; later scans drop findings whose fingerprint
appears in the file. Combined with ``--fail-on error`` this *is*
fail-on-new — no extra flag needed. Fingerprint v2 is line-independent,
so baselined findings stay suppressed while unrelated code shifts around
them.

The file lives in (and is loaded from) the scanned repo, so treat its
contents as untrusted input: it is schema-validated, size-capped, and can
only ever *remove* findings — never add text to a report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from repomedic.models import AnalyzerResult, ScanReport

BASELINE_FILENAME = ".repomedic-baseline.json"

MAX_BASELINE_BYTES = 10 * 1024 * 1024


class BaselineFile(BaseModel):
    """On-disk baseline: the fingerprints a repo has chosen to accept."""

    schema_version: int = 1
    created: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fingerprints: list[str] = Field(default_factory=list)


class BaselineError(Exception):
    """The baseline file is missing, oversized, or not a valid baseline."""


def write_baseline(report: ScanReport, path: Path) -> BaselineFile:
    """Snapshot every fingerprint in the report to *path*. Returns the model."""
    fingerprints = sorted({f.fingerprint for f in report.findings if f.fingerprint})
    baseline = BaselineFile(fingerprints=fingerprints)
    path.write_text(baseline.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return baseline


def load_baseline(path: Path) -> set[str]:
    """Load the fingerprint set from a baseline file, validating shape and size."""
    try:
        if path.stat().st_size > MAX_BASELINE_BYTES:
            raise BaselineError(f"baseline file too large (> {MAX_BASELINE_BYTES} bytes): {path}")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline file {path}: {exc}") from exc
    try:
        baseline = BaselineFile.model_validate_json(text)
    except ValidationError as exc:
        raise BaselineError(f"invalid baseline file {path}: {exc}") from exc
    return set(baseline.fingerprints)


def apply_baseline(results: list[AnalyzerResult], fingerprints: set[str]) -> int:
    """Drop baselined findings in place. Returns how many were dropped."""
    suppressed = 0
    for result in results:
        kept = [f for f in result.findings if f.fingerprint not in fingerprints]
        suppressed += len(result.findings) - len(kept)
        result.findings = kept
    return suppressed
