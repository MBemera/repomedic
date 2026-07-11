"""Content-aware fingerprint assignment for scan results.

The scanner calls :func:`assign_fingerprints` once per scan (via
``core.postprocess``), before any filtering or truncation, so a
fingerprint is a property of the repo's state — not of the flags used
for a particular run.

For a finding with a resolvable file and line, the hashed content is the
normalized text of the flagged line; findings that share (code, file,
content) — e.g. two identical hardcoded secrets — are disambiguated by an
occurrence index in line order. Findings without a usable line fall back
to title/description content (same scheme as the model-level default).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from repomedic.models import AnalyzerResult, Finding, compute_fingerprint, normalize_line

if TYPE_CHECKING:
    from pathlib import Path

    from repomedic.core.postprocess import LineCache


def assign_fingerprints(
    results: list[AnalyzerResult], root: Path, cache: LineCache | None = None
) -> None:
    """Assign v2 fingerprints to every finding, in place."""
    if cache is None:
        from repomedic.core.postprocess import LineCache

        cache = LineCache(root)

    def content_for(finding: Finding) -> str:
        if finding.file_path and finding.line:
            file_lines = cache.lines(finding.file_path)
            if file_lines and 1 <= finding.line <= len(file_lines):
                return normalize_line(file_lines[finding.line - 1])
        if finding.file_path:
            return normalize_line(finding.title)
        return normalize_line(f"{finding.title}|{finding.description[:80]}")

    # Group by identity key, then disambiguate duplicates by line order.
    grouped: dict[tuple[str, str | None, str], list[tuple[int, int, Finding, str]]] = {}
    order = 0
    for result in results:
        for finding in result.findings:
            content = content_for(finding)
            key = (finding.code, finding.file_path, content)
            grouped.setdefault(key, []).append((finding.line or 0, order, finding, content))
            order += 1

    for (code, file_path, content), entries in grouped.items():
        entries.sort(key=lambda e: (e[0], e[1]))
        for occurrence, (_line, _order, finding, entry_content) in enumerate(entries):
            finding.fingerprint = compute_fingerprint(code, file_path, entry_content, occurrence)
