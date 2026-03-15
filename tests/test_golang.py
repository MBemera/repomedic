"""Tests for the Go analyzer."""

from __future__ import annotations

from repomedic.analyzers.golang import GoAnalyzer
from repomedic.core.context import ScanContext


def test_applicable_with_go_files(make_project):
    project = make_project({"main.go": "package main\n\nfunc main() {}\n"})
    ctx = ScanContext(str(project))
    analyzer = GoAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_applicable_with_go_mod(make_project):
    project = make_project({"go.mod": "module example.com/test\n\ngo 1.21\n"})
    ctx = ScanContext(str(project))
    analyzer = GoAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_not_applicable_without_go(make_project):
    project = make_project({"hello.py": "print('hello')\n"})
    ctx = ScanContext(str(project))
    analyzer = GoAnalyzer()
    assert not analyzer.is_applicable(ctx)


def test_missing_go_mod(make_project):
    project = make_project({"main.go": "package main\n\nfunc main() {}\n"})
    ctx = ScanContext(str(project))
    analyzer = GoAnalyzer()
    result = analyzer.analyze(ctx)

    mod_findings = [f for f in result.findings if f.code == "GO-DEP-001"]
    assert len(mod_findings) == 1
    assert mod_findings[0].language == "go"


def test_missing_go_sum(make_project):
    project = make_project({
        "main.go": "package main\n\nfunc main() {}\n",
        "go.mod": "module example.com/test\n\ngo 1.21\n",
    })
    ctx = ScanContext(str(project))
    analyzer = GoAnalyzer()
    result = analyzer.analyze(ctx)

    sum_findings = [f for f in result.findings if f.code == "GO-DEP-003"]
    assert len(sum_findings) == 1
