"""Tests for the hygiene analyzer."""

from __future__ import annotations

import os

from repomedic.analyzers.hygiene import HygieneAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import Severity


def test_clean_project_no_findings(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    result = HygieneAnalyzer().analyze(ctx)
    assert result.findings == []


def test_large_file_flagged(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    big = project / "dump.csv"
    with open(big, "wb") as f:
        f.seek(11 * 1024 * 1024 - 1)
        f.write(b"\0")

    ctx = ScanContext(str(project))
    result = HygieneAnalyzer().analyze(ctx)

    large = [f for f in result.findings if f.code == "HYG-001"]
    assert len(large) == 1
    assert large[0].file_path == "dump.csv"
    assert large[0].severity == Severity.warning


def test_todo_density_reported_above_threshold(make_project):
    lines = "\n".join(f"x{i} = {i}  # TODO fix this" for i in range(12))
    project = make_project({"app.py": lines + "\n"})
    ctx = ScanContext(str(project))
    result = HygieneAnalyzer().analyze(ctx)

    todos = [f for f in result.findings if f.code == "HYG-002"]
    assert len(todos) == 1
    assert "12 TODO/FIXME markers" in todos[0].title


def test_few_todos_not_reported(make_project):
    project = make_project({"app.py": "# TODO one thing\nx = 1\n"})
    ctx = ScanContext(str(project))
    result = HygieneAnalyzer().analyze(ctx)
    assert not [f for f in result.findings if f.code == "HYG-002"]


def test_broken_symlink_flagged(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    os.symlink(project / "does-not-exist.txt", project / "dangling")

    ctx = ScanContext(str(project))
    result = HygieneAnalyzer().analyze(ctx)

    broken = [f for f in result.findings if f.code == "HYG-003"]
    assert len(broken) == 1
    assert broken[0].file_path == "dangling"
