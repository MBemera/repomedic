"""Scanner orchestrator — runs analyzers and builds ScanReport."""

from __future__ import annotations

import time

from repomedic.analyzers import get_all_analyzers
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, ScanReport


class Scanner:
    """Discovers and runs applicable analyzers against a target directory."""

    def scan(
        self,
        target: str,
        analyzer_names: list[str] | None = None,
        min_severity: str | None = None,
        skip_tests: bool = True,
    ) -> ScanReport:
        ctx = ScanContext(target, skip_tests=skip_tests)
        analyzers = get_all_analyzers()

        if analyzer_names:
            names = {n.strip().lower() for n in analyzer_names}
            analyzers = [a for a in analyzers if a.name in names]

        report = ScanReport(target=str(ctx.target))

        for analyzer in analyzers:
            if not analyzer.is_applicable(ctx):
                continue

            start = time.monotonic()
            try:
                result = analyzer.analyze(ctx)
            except Exception as exc:
                result = AnalyzerResult(
                    analyzer=analyzer.name,
                    error=f"{type(exc).__name__}: {exc}",
                )
            result.elapsed_seconds = round(time.monotonic() - start, 3)
            report.results.append(result)

        # Filter by severity if requested
        if min_severity:
            severity_order = {"error": 0, "warning": 1, "info": 2}
            threshold = severity_order.get(min_severity, 2)
            for r in report.results:
                r.findings = [
                    f
                    for f in r.findings
                    if severity_order.get(f.severity.value, 2) <= threshold
                ]

        report.build_summary()

        # Run doctor and explain automatically and attach to report
        from pathlib import Path
        from repomedic.commands.doctor import run_doctor
        from repomedic.commands.explain import run_explain

        target_path = Path(target).resolve()
        report.doctor_results = run_doctor(target_path)
        report.explain_results = run_explain(target_path)

        return report
