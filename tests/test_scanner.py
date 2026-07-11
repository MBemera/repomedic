"""Tests for the Scanner orchestrator."""

from __future__ import annotations


from repomedic.core.scanner import Scanner
from repomedic.models import ScanReport, Severity


def test_scan_returns_report(fixtures_dir):
    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), skip_tests=False)

    assert isinstance(report, ScanReport)
    assert report.target == str(fixtures_dir / "broken_imports")
    assert len(report.results) > 0


def test_scan_filter_by_analyzer(fixtures_dir):
    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), analyzer_names=["static"], skip_tests=False)

    assert len(report.results) == 1
    assert report.results[0].analyzer == "static"


def test_scan_filter_by_severity(fixtures_dir):
    scanner = Scanner()
    # "static" analyzer triggers both ERR (syntax) and WARN (unused import) in the fixtures
    report = scanner.scan(str(fixtures_dir / "broken_imports"), analyzer_names=["static"], min_severity="error", skip_tests=False)

    # Only error findings should remain
    for result in report.results:
        for finding in result.findings:
            assert finding.severity == Severity.error


def test_scan_fixture_broken_imports(fixtures_dir):
    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), skip_tests=False)

    assert report.summary.total_findings > 0
    assert report.summary.errors > 0


def test_scan_json_roundtrip(fixtures_dir):
    """Ensure report serializes to valid JSON and back."""
    import json

    scanner = Scanner()
    report = scanner.scan(str(fixtures_dir / "broken_imports"), skip_tests=False)
    data = json.loads(report.model_dump_json())

    assert "summary" in data
    assert "results" in data
    assert isinstance(data["results"], list)


def test_scan_detects_languages(fixtures_dir):
    report = Scanner().scan(str(fixtures_dir / "broken_imports"), skip_tests=False)
    assert "python" in report.languages
    assert report.files_scanned > 0


def test_scan_max_findings_keeps_most_severe(fixtures_dir):
    full = Scanner().scan(str(fixtures_dir / "broken_imports"), skip_tests=False)
    assert full.summary.total_findings > 1

    capped = Scanner().scan(str(fixtures_dir / "broken_imports"), skip_tests=False, max_findings=1)
    kept = capped.findings
    assert len(kept) == 1
    assert kept[0].severity == Severity.error  # most severe survives
    assert capped.summary.omitted_findings == capped.summary.total_findings - 1
    # Summary still reflects the full scan
    assert capped.summary.total_findings == full.summary.total_findings


def test_scan_only_files_filter(fixtures_dir):
    target = fixtures_dir / "broken_imports"
    full = Scanner().scan(str(target), analyzer_names=["static"], skip_tests=False)
    all_paths = {f.file_path for f in full.findings if f.file_path}
    assert "bad_syntax.py" in all_paths

    filtered = Scanner().scan(
        str(target),
        analyzer_names=["static"],
        skip_tests=False,
        only_files={"bad_syntax.py"},
    )
    kept_paths = {f.file_path for f in filtered.findings if f.file_path}
    assert kept_paths <= {"bad_syntax.py"}


def test_scan_extra_ignore_dirs(make_project):
    project = make_project({
        "app.py": "x = 1\n",
        "generated/broken.py": "def broken(:\n    pass\n",
    })
    report = Scanner().scan(str(project), analyzer_names=["static"])
    assert report.summary.errors > 0

    report_ignored = Scanner().scan(
        str(project), analyzer_names=["static"], extra_ignore_dirs={"generated"}
    )
    assert report_ignored.summary.errors == 0


def test_scan_emits_analyzer_progress_events(make_project):
    project = make_project({
        "app.py": "x = 1\n",
        "config.json": "{}\n",
    })
    events: list[tuple[str, str, int, int]] = []

    report = Scanner().scan(
        str(project), on_analyzer=lambda *event: events.append(event)
    )

    total = len(report.results)
    assert total > 1  # the parallel path is the one that matters
    starts = [e for e in events if e[0] == "start"]
    finishes = [e for e in events if e[0] in ("done", "timeout")]
    assert len(starts) == total
    assert len(finishes) == total
    assert {e[1] for e in starts} == {r.analyzer for r in report.results}
    assert all(e[3] == total for e in events)
    assert finishes[-1][2] == total  # completed count reaches the total


def test_scan_emits_events_for_single_analyzer(make_project):
    project = make_project({"app.py": "x = 1\n"})
    events: list[tuple[str, str, int, int]] = []

    Scanner().scan(
        str(project),
        analyzer_names=["static"],
        on_analyzer=lambda *event: events.append(event),
    )

    assert events == [("start", "static", 0, 1), ("done", "static", 1, 1)]


def test_finding_fingerprints_stable_and_serialized(fixtures_dir):
    import json

    r1 = Scanner().scan(str(fixtures_dir / "broken_imports"), analyzer_names=["static"], skip_tests=False)
    r2 = Scanner().scan(str(fixtures_dir / "broken_imports"), analyzer_names=["static"], skip_tests=False)

    fp1 = [f.fingerprint for f in r1.findings]
    fp2 = [f.fingerprint for f in r2.findings]
    assert fp1 == fp2  # stable across runs
    assert all(fp.startswith("RM-") for fp in fp1)

    data = json.loads(r1.model_dump_json())
    serialized = [f["fingerprint"] for r in data["results"] for f in r["findings"]]
    assert serialized == fp1  # computed field lands in JSON


def test_analyzer_timeout_abandons_slow_analyzer(make_project, monkeypatch):
    """A hung analyzer becomes an error entry; the scan still completes."""
    import time as time_mod

    from repomedic.analyzers.base import BaseAnalyzer
    from repomedic.core import scanner as scanner_mod
    from repomedic.models import AnalyzerResult

    class SlowAnalyzer(BaseAnalyzer):
        name = "slow-fake"
        description = "hangs"

        def is_applicable(self, ctx):
            return True

        def analyze(self, ctx):
            time_mod.sleep(5)
            return AnalyzerResult(analyzer=self.name)

    class FastAnalyzer(BaseAnalyzer):
        name = "fast-fake"
        description = "returns instantly"

        def is_applicable(self, ctx):
            return True

        def analyze(self, ctx):
            return AnalyzerResult(analyzer=self.name)

    monkeypatch.setattr(
        scanner_mod, "get_all_analyzers", lambda: [SlowAnalyzer(), FastAnalyzer()]
    )
    project = make_project({"app.py": "x = 1\n"})

    start = time_mod.monotonic()
    report = Scanner().scan(str(project), analyzer_timeout=0.5)
    elapsed = time_mod.monotonic() - start

    assert elapsed < 4  # did not wait for the hung analyzer
    by_name = {r.analyzer: r for r in report.results}
    assert "Timed out" in (by_name["slow-fake"].error or "")
    assert by_name["fast-fake"].error is None
    assert report.summary.analyzers_failed == 1
