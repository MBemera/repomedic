"""Inline suppression directives: ``# repomedic: ignore[CODE]``.

A finding is suppressed when its flagged line — or the line directly
above it — carries a directive that matches the finding's code:

- ``# repomedic: ignore`` (bare) suppresses every finding on that line
- ``# repomedic: ignore[STATIC-001]`` suppresses that exact code
- ``# repomedic: ignore[STATIC-*]`` suppresses codes with that prefix
- ``# repomedic: ignore[STATIC-001, SEC-002]`` — comma-separated list

The directive is matched anywhere in the line, so it works behind any
comment marker (``#``, ``//``, ``--``, ``;``). Matching is
case-insensitive. Findings without a file and line cannot be suppressed
inline — use the baseline for those.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from repomedic.models import AnalyzerResult, Finding

if TYPE_CHECKING:
    from repomedic.core.postprocess import LineCache

DIRECTIVE_RE = re.compile(r"repomedic:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)

BARE_DIRECTIVE: list[str] = []


def parse_directive(line: str) -> list[str] | None:
    """Return the directive's code patterns, [] for bare ignore, None if absent."""
    match = DIRECTIVE_RE.search(line)
    if match is None:
        return None
    raw = match.group(1)
    if raw is None:
        return BARE_DIRECTIVE
    patterns = [p.strip().upper() for p in raw.split(",") if p.strip()]
    return patterns if patterns else BARE_DIRECTIVE


def directive_matches(code: str, patterns: list[str]) -> bool:
    """True when a bare directive or any exact/prefix-wildcard pattern hits."""
    if patterns == BARE_DIRECTIVE:
        return True
    code = code.upper()
    for pattern in patterns:
        if pattern.endswith("*"):
            if code.startswith(pattern[:-1]):
                return True
        elif code == pattern:
            return True
    return False


def is_suppressed(finding: Finding, cache: LineCache) -> bool:
    """Check the flagged line and the line above for a matching directive."""
    if not finding.file_path or not finding.line:
        return False
    lines = cache.lines(finding.file_path)
    if not lines:
        return False
    for line_number in (finding.line, finding.line - 1):
        if 1 <= line_number <= len(lines):
            patterns = parse_directive(lines[line_number - 1])
            if patterns is not None and directive_matches(finding.code, patterns):
                return True
    return False


def apply_inline_suppressions(results: list[AnalyzerResult], cache: LineCache) -> int:
    """Drop inline-suppressed findings in place. Returns how many were dropped."""
    suppressed = 0
    for result in results:
        kept = [f for f in result.findings if not is_suppressed(f, cache)]
        suppressed += len(result.findings) - len(kept)
        result.findings = kept
    return suppressed
