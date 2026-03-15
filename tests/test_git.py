"""Tests for the git analyzer."""

from __future__ import annotations

import subprocess

from repomedic.analyzers.git import GitAnalyzer
from repomedic.core.context import ScanContext


def test_merge_conflict_detected(make_project):
    project = make_project({
        "conflict.py": '<<<<<<< HEAD\nreturn "hello"\n=======\nreturn "hi"\n>>>>>>> feature\n',
    })
    # Need a .git dir for the analyzer to be applicable, but we test
    # the merge conflict scanning method directly
    ctx = ScanContext(str(project))
    analyzer = GitAnalyzer()
    findings = analyzer._check_merge_conflicts(ctx)

    assert len(findings) == 1
    assert findings[0].code == "GIT-003"
    assert findings[0].severity.value == "error"


def test_not_applicable_without_git(make_project):
    project = make_project({"app.py": "print('hi')\n"})
    ctx = ScanContext(str(project))
    analyzer = GitAnalyzer()
    assert not analyzer.is_applicable(ctx)


def test_git_status_in_repo(tmp_path):
    """Test git analyzer in a real git repo."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(tmp_path), capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(tmp_path), capture_output=True,
    )

    # Create and commit a file
    (tmp_path / "hello.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), capture_output=True)

    # Modify file to create uncommitted changes
    (tmp_path / "hello.py").write_text("print('changed')\n")

    ctx = ScanContext(str(tmp_path))
    analyzer = GitAnalyzer()
    assert analyzer.is_applicable(ctx)

    result = analyzer.analyze(ctx)
    codes = [f.code for f in result.findings]
    assert "GIT-001" in codes  # uncommitted changes
