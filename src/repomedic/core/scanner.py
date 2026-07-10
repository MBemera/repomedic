"""Scanner orchestrator — runs analyzers and builds ScanReport.

The scanner is side-effect free: it never prints, prompts, or writes files.
All presentation lives in the output layer, which keeps stdout clean for
machine consumers (agents, CI) and makes the scan embeddable as a library.
"""

from __future__ import annotations

import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import PurePosixPath

from repomedic.analyzers import get_all_analyzers
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import SEVERITY_ORDER, AnalyzerResult, Finding, ScanReport

MAX_PARALLEL_ANALYZERS = 4

# Wall-clock budget per analyzer before the scanner stops waiting for it.
DEFAULT_ANALYZER_TIMEOUT = 120.0


class Scanner:
    """Discovers and runs applicable analyzers against a target directory."""

    def scan(
        self,
        target: str,
        analyzer_names: list[str] | None = None,
        min_severity: str | None = None,
        skip_tests: bool = True,
        extra_ignore_dirs: set[str] | None = None,
        only_files: set[str] | None = None,
        max_findings: int | None = None,
        analyzer_timeout: float | None = DEFAULT_ANALYZER_TIMEOUT,
    ) -> ScanReport:
        """Run applicable analyzers and return a ScanReport.

        Args:
            target: Directory to scan.
            analyzer_names: Restrict to these analyzers (None = all applicable).
            min_severity: Drop findings below this severity (error > warning > info).
            skip_tests: Skip test files/directories during file discovery.
            extra_ignore_dirs: Additional directory names to exclude.
            only_files: Repo-relative paths — keep only findings in these files
                (project-level findings are kept). Used for --changed scans.
            max_findings: Truncate to the N most severe findings (0/None = no cap).
            analyzer_timeout: Wall-clock seconds an analyzer may run before the
                scanner abandons it (its result becomes an error entry).
                None/0 disables the deadline.
        """
        start = time.monotonic()
        ctx = ScanContext(target, skip_tests=skip_tests, extra_ignore_dirs=extra_ignore_dirs)
        analyzers = get_all_analyzers()

        if analyzer_names:
            names = {n.strip().lower() for n in analyzer_names}
            analyzers = [a for a in analyzers if a.name in names]

        report = ScanReport(target=str(ctx.target))
        # Warm the shared lazy caches on the main thread so worker threads
        # only ever read them — ScanContext has no locks.
        report.languages = ctx.language_counts
        report.files_scanned = len(ctx.files)
        ctx.files_by_language  # noqa: B018 — intentional cache warmup

        applicable = [a for a in analyzers if a.is_applicable(ctx)]

        # Analyzers are subprocess/I/O bound, so a small thread pool speeds up
        # scans considerably. Results keep registration order for determinism.
        if len(applicable) > 1:
            results = _run_parallel(applicable, ctx, analyzer_timeout)
        else:
            results = [_run_analyzer(a, ctx) for a in applicable]
        report.results = results

        if only_files is not None:
            _filter_to_files(report, only_files)

        if min_severity:
            threshold = SEVERITY_ORDER.get(min_severity, 2)
            for r in report.results:
                r.findings = [
                    f for f in r.findings if SEVERITY_ORDER.get(f.severity.value, 2) <= threshold
                ]

        # Summary reflects the full scan; truncation only trims the body and
        # records how many findings were omitted.
        report.build_summary()

        if max_findings:
            _truncate(report, max_findings)

        report.duration_seconds = round(time.monotonic() - start, 3)
        return report


def _run_analyzer(analyzer: BaseAnalyzer, ctx: ScanContext) -> AnalyzerResult:
    """Run one analyzer, capturing exceptions and timing."""
    start = time.monotonic()
    try:
        result = analyzer.analyze(ctx)
    except Exception as exc:
        result = AnalyzerResult(
            analyzer=analyzer.name,
            error=f"{type(exc).__name__}: {exc}",
        )
    result.elapsed_seconds = round(time.monotonic() - start, 3)
    return result


def _run_parallel(
    applicable: list[BaseAnalyzer],
    ctx: ScanContext,
    analyzer_timeout: float | None,
) -> list[AnalyzerResult]:
    """Run analyzers in a thread pool with a per-analyzer wall-clock deadline.

    Threads cannot be killed, so a deadline expiry *abandons* the analyzer:
    its result becomes an error entry and the scan moves on, while the
    orphaned thread winds down on its own subprocess timeouts (every
    blocking call inside analyzers is a `utils.process.run` with a timeout).
    A global cap of ``timeout * len(applicable)`` bounds the whole batch even
    if every worker hangs.
    """
    starts: dict[str, float] = {}

    def timed_run(a: BaseAnalyzer) -> AnalyzerResult:
        starts[a.name] = time.monotonic()
        return _run_analyzer(a, ctx)

    executor = ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_ANALYZERS, len(applicable)))
    pending = {a.name: executor.submit(timed_run, a) for a in applicable}
    results: dict[str, AnalyzerResult] = {}
    hard_deadline = (
        time.monotonic() + analyzer_timeout * len(applicable) if analyzer_timeout else None
    )

    while pending:
        wait(pending.values(), timeout=0.2, return_when=FIRST_COMPLETED)
        now = time.monotonic()
        for name, future in list(pending.items()):
            timed_out = analyzer_timeout and (
                (name in starts and now - starts[name] > analyzer_timeout)
                or (hard_deadline is not None and now > hard_deadline)
            )
            if future.done():
                results[name] = future.result()
                del pending[name]
            elif timed_out:
                elapsed = round(now - starts.get(name, now), 3)
                results[name] = AnalyzerResult(
                    analyzer=name,
                    error=f"Timed out after {analyzer_timeout:.0f}s (analyzer abandoned)",
                    elapsed_seconds=elapsed,
                )
                del pending[name]

    executor.shutdown(wait=False, cancel_futures=True)
    return [results[a.name] for a in applicable]


def _filter_to_files(report: ScanReport, only_files: set[str]) -> None:
    """Keep findings located in *only_files*; project-level findings survive."""
    normalized = {str(PurePosixPath(p)) for p in only_files}
    for r in report.results:
        r.findings = [
            f
            for f in r.findings
            if f.file_path is None or str(PurePosixPath(f.file_path)) in normalized
        ]


def _truncate(report: ScanReport, max_findings: int) -> None:
    """Keep only the *max_findings* most severe findings; record how many were dropped.

    Each finding is tagged with (severity_rank, discovery_order). Sorting by that
    pair puts errors first, then warnings, then infos, and — because the second
    element is a simple counter — preserves the original order within each
    severity so the output is deterministic. We then keep that many findings and
    drop the rest, matching by object identity (id()) since two findings can be
    otherwise equal.
    """
    ranked: list[tuple[int, int, Finding]] = []
    order = 0
    for r in report.results:
        for f in r.findings:
            ranked.append((SEVERITY_ORDER.get(f.severity.value, 2), order, f))
            order += 1
    if len(ranked) <= max_findings:
        return

    ranked.sort(key=lambda t: (t[0], t[1]))
    keep = {id(f) for _, _, f in ranked[:max_findings]}
    for r in report.results:
        r.findings = [f for f in r.findings if id(f) in keep]
    report.summary.omitted_findings = len(ranked) - max_findings
