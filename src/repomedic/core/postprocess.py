"""Post-scan result pipeline: fingerprints, inline suppressions, baseline.

Runs once in ``Scanner.scan`` right after the analyzers finish and before
any severity filtering or truncation, so fingerprints and suppressions are
properties of the repo state — not of the flags used for a particular run.

All three passes share one :class:`LineCache` so each flagged file is read
from disk at most once per scan.
"""

from __future__ import annotations

from pathlib import Path

from repomedic.core.baseline import apply_baseline
from repomedic.core.fingerprint import assign_fingerprints
from repomedic.core.suppress import apply_inline_suppressions
from repomedic.models import AnalyzerResult
from repomedic.utils.fs import read_text_capped


class LineCache:
    """Reads repo files as line lists, at most once each, contained to root.

    Same containment rule as snippet rendering: a path that resolves
    outside the scan root (e.g. via symlink) is never read.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root_resolved = root.resolve()
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, file_path: str) -> list[str] | None:
        if file_path not in self._cache:
            path = (self._root / file_path).resolve(strict=False)
            if not path.is_relative_to(self._root_resolved) or not path.is_file():
                self._cache[file_path] = None
            else:
                text = read_text_capped(path)
                self._cache[file_path] = text.splitlines() if text is not None else None
        return self._cache[file_path]


def postprocess_results(
    results: list[AnalyzerResult],
    root: Path,
    baseline_fingerprints: set[str] | None = None,
) -> int:
    """Fingerprint every finding, then drop suppressed ones. Returns drop count."""
    cache = LineCache(root)
    assign_fingerprints(results, root, cache=cache)
    suppressed = apply_inline_suppressions(results, cache)
    if baseline_fingerprints:
        suppressed += apply_baseline(results, baseline_fingerprints)
    return suppressed
