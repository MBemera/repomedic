"""Tests for the fix command."""

from __future__ import annotations

from repomedic.commands.fix import _fix_env_example, _fix_gitignore


def test_fix_gitignore_creates_when_missing(tmp_path):
    action, desc, status = _fix_gitignore(tmp_path)
    assert status == "FIXED"
    assert (tmp_path / ".gitignore").is_file()
    content = (tmp_path / ".gitignore").read_text()
    assert "__pycache__/" in content
    assert ".env" in content


def test_fix_gitignore_skips_when_exists(tmp_path):
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    action, desc, status = _fix_gitignore(tmp_path)
    assert status == "SKIPPED"


def test_fix_env_example_creates(tmp_path):
    (tmp_path / ".env").write_text("SECRET_KEY=abc123\nDB_URL=postgres://...\n")
    action, desc, status = _fix_env_example(tmp_path)
    assert status == "FIXED"
    example = (tmp_path / ".env.example").read_text()
    assert "SECRET_KEY=" in example
    assert "abc123" not in example


def test_fix_env_example_skips_when_no_env(tmp_path):
    action, desc, status = _fix_env_example(tmp_path)
    assert status == "SKIPPED"


def test_fix_env_example_skips_when_exists(tmp_path):
    (tmp_path / ".env").write_text("KEY=val\n")
    (tmp_path / ".env.example").write_text("KEY=\n")
    action, desc, status = _fix_env_example(tmp_path)
    assert status == "SKIPPED"
