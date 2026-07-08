"""Tests for the shell analyzer."""

from __future__ import annotations

import shutil

import pytest

from repomedic.analyzers.shell import ShellAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import Severity

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")


def test_not_applicable_without_shell_files(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    assert not ShellAnalyzer().is_applicable(ctx)


def test_applicable_with_shell_files(make_project):
    project = make_project({"run.sh": "echo hi\n"})
    ctx = ScanContext(str(project))
    assert ShellAnalyzer().is_applicable(ctx)


@needs_bash
def test_valid_script_no_syntax_findings(make_project):
    project = make_project({"run.sh": '#!/bin/bash\necho "hello"\n'})
    ctx = ScanContext(str(project))
    result = ShellAnalyzer().analyze(ctx)
    assert not [f for f in result.findings if f.code == "SH-001"]


@needs_bash
def test_syntax_error_detected(make_project):
    project = make_project({"broken.sh": '#!/bin/bash\nfor i in 1 2 3\necho "missing do/done"\n'})
    ctx = ScanContext(str(project))
    result = ShellAnalyzer().analyze(ctx)

    syntax = [f for f in result.findings if f.code == "SH-001"]
    assert len(syntax) == 1
    assert syntax[0].severity == Severity.error
    assert syntax[0].file_path == "broken.sh"
    assert syntax[0].language == "shell"
