"""Tests for git changed-file discovery."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from repomedic.utils.vcs import changed_files

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    (tmp_path / "committed.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_non_git_dir_returns_none(tmp_path):
    assert changed_files(tmp_path) is None


@needs_git
def test_clean_repo_has_no_changes(git_repo):
    assert changed_files(git_repo) == set()


@needs_git
def test_untracked_files_in_new_dirs_listed_individually(git_repo):
    sub = git_repo / "src"
    sub.mkdir()
    (sub / "new.py").write_text("y = 2\n")

    changed = changed_files(git_repo)
    assert changed == {"src/new.py"}


@needs_git
def test_modified_files_listed(git_repo):
    (git_repo / "committed.py").write_text("x = 2\n")
    assert changed_files(git_repo) == {"committed.py"}


@needs_git
def test_since_ref(git_repo):
    (git_repo / "committed.py").write_text("x = 2\n")
    _git(git_repo, "commit", "-aqm", "change")
    (git_repo / "untracked.py").write_text("z = 3\n")

    changed = changed_files(git_repo, since="HEAD~1")
    assert changed == {"committed.py", "untracked.py"}
