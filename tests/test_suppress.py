"""Tests for inline `repomedic: ignore` suppression directives."""

from __future__ import annotations

from pathlib import Path

from repomedic.core.postprocess import LineCache, postprocess_results
from repomedic.core.suppress import (
    apply_inline_suppressions,
    directive_matches,
    parse_directive,
)
from repomedic.models import AnalyzerResult, Category, Finding, Severity


def _finding(code: str, file_path: str, line: int) -> Finding:
    return Finding(
        category=Category.static_analysis,
        severity=Severity.warning,
        code=code,
        title="Flagged",
        description="Something flagged",
        file_path=file_path,
        line=line,
    )


class TestParseDirective:
    def test_no_directive(self):
        assert parse_directive("x = compute()  # just a comment") is None

    def test_bare_directive(self):
        assert parse_directive("x = risky()  # repomedic: ignore") == []

    def test_exact_code(self):
        assert parse_directive("# repomedic: ignore[STATIC-001]") == ["STATIC-001"]

    def test_comma_separated_codes(self):
        assert parse_directive("# repomedic: ignore[STATIC-001, SEC-002]") == [
            "STATIC-001",
            "SEC-002",
        ]

    def test_case_insensitive_and_comment_marker_agnostic(self):
        assert parse_directive("// REPOMEDIC: IGNORE[sec-001]") == ["SEC-001"]

    def test_empty_brackets_treated_as_bare(self):
        assert parse_directive("# repomedic: ignore[]") == []


class TestDirectiveMatches:
    def test_bare_matches_everything(self):
        assert directive_matches("ANY-123", [])

    def test_exact_match(self):
        assert directive_matches("STATIC-001", ["STATIC-001"])
        assert not directive_matches("STATIC-002", ["STATIC-001"])

    def test_prefix_wildcard(self):
        assert directive_matches("SEC-004", ["SEC-*"])
        assert not directive_matches("STATIC-001", ["SEC-*"])


def test_trailing_directive_suppresses(make_project):
    project = make_project({"app.py": "import os  # repomedic: ignore[STATIC-*]\n"})
    results = [AnalyzerResult(analyzer="static", findings=[_finding("STATIC-001", "app.py", 1)])]

    dropped = apply_inline_suppressions(results, LineCache(project))
    assert dropped == 1
    assert results[0].findings == []


def test_line_above_directive_suppresses(make_project):
    project = make_project(
        {"app.py": "# repomedic: ignore[SEC-001]\npassword = 'x'\n"}
    )
    results = [AnalyzerResult(analyzer="security", findings=[_finding("SEC-001", "app.py", 2)])]

    dropped = apply_inline_suppressions(results, LineCache(project))
    assert dropped == 1


def test_non_matching_code_is_kept(make_project):
    project = make_project({"app.py": "import os  # repomedic: ignore[SEC-001]\n"})
    results = [AnalyzerResult(analyzer="static", findings=[_finding("STATIC-001", "app.py", 1)])]

    dropped = apply_inline_suppressions(results, LineCache(project))
    assert dropped == 0
    assert len(results[0].findings) == 1


def test_project_level_findings_cannot_be_suppressed_inline(make_project):
    project = make_project({"app.py": "# repomedic: ignore\n"})
    finding = Finding(
        category=Category.git_health,
        severity=Severity.warning,
        code="GIT-001",
        title="No repo",
        description="Not a git repository",
    )
    results = [AnalyzerResult(analyzer="git", findings=[finding])]

    dropped = apply_inline_suppressions(results, LineCache(project))
    assert dropped == 0


def test_postprocess_assigns_fingerprints_then_suppresses(make_project):
    project = make_project(
        {"app.py": "import os\nimport sys  # repomedic: ignore\n"}
    )
    kept = _finding("STATIC-001", "app.py", 1)
    suppressed = _finding("STATIC-001", "app.py", 2)
    results = [AnalyzerResult(analyzer="static", findings=[kept, suppressed])]

    dropped = postprocess_results(results, Path(project))

    assert dropped == 1
    assert results[0].findings == [kept]
    assert kept.fingerprint.startswith("RM-")


def test_postprocess_applies_baseline_after_suppressions(make_project):
    project = make_project({"app.py": "import os\nimport sys\n"})
    first = _finding("STATIC-001", "app.py", 1)
    second = _finding("STATIC-001", "app.py", 2)
    results = [AnalyzerResult(analyzer="static", findings=[first, second])]
    postprocess_results(results, Path(project))
    baselined = first.fingerprint

    fresh_first = _finding("STATIC-001", "app.py", 1)
    fresh_second = _finding("STATIC-001", "app.py", 2)
    fresh = [AnalyzerResult(analyzer="static", findings=[fresh_first, fresh_second])]
    dropped = postprocess_results(fresh, Path(project), baseline_fingerprints={baselined})

    assert dropped == 1
    assert fresh[0].findings == [fresh_second]


def test_scan_counts_suppressed_in_summary(make_project):
    from repomedic.core.scanner import Scanner

    project = make_project(
        {
            "app.py": "import os  # repomedic: ignore\n",
            "other.py": "import sys\n",
        }
    )
    report = Scanner().scan(str(project), analyzer_names=["static"])
    codes_files = [(f.code, f.file_path) for f in report.findings]

    assert all(path != "app.py" for _code, path in codes_files)
    assert report.summary.suppressed_findings >= 1
