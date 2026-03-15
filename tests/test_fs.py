"""Tests for the file discovery utilities."""

from __future__ import annotations

from pathlib import Path

from repomedic.utils.fs import _is_test_file, discover_files


def test_discover_files_basic(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')")
    (tmp_path / "utils.py").write_text("x = 1")
    files = discover_files(tmp_path, skip_tests=False)
    assert len(files) == 2


def test_discover_files_ignores_pycache(tmp_path):
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "app.cpython-311.pyc").write_bytes(b"")
    (tmp_path / "app.py").write_text("print('hi')")
    files = discover_files(tmp_path, skip_tests=False)
    assert len(files) == 1
    assert files[0].name == "app.py"


def test_discover_files_skip_tests(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')")
    (tmp_path / "test_app.py").write_text("def test_it(): pass")
    files = discover_files(tmp_path, skip_tests=True)
    names = [f.name for f in files]
    assert "app.py" in names
    assert "test_app.py" not in names


def test_discover_files_include_tests(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')")
    (tmp_path / "test_app.py").write_text("def test_it(): pass")
    files = discover_files(tmp_path, skip_tests=False)
    names = [f.name for f in files]
    assert "test_app.py" in names


def test_discover_files_filter_extensions(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')")
    (tmp_path / "readme.md").write_text("# Hello")
    files = discover_files(tmp_path, extensions={".py"}, skip_tests=False)
    assert len(files) == 1
    assert files[0].name == "app.py"


def test_is_test_file():
    assert _is_test_file("test_app.py") is True
    assert _is_test_file("app_test.py") is True
    assert _is_test_file("app_test.js") is True
    assert _is_test_file("app.spec.ts") is True
    assert _is_test_file("app.py") is False
    assert _is_test_file("testing.py") is False


def test_discover_files_ignores_node_modules(tmp_path):
    nm_dir = tmp_path / "node_modules"
    nm_dir.mkdir()
    (nm_dir / "pkg.js").write_text("module.exports = {}")
    (tmp_path / "app.js").write_text("console.log('hi')")
    files = discover_files(tmp_path, skip_tests=False)
    assert len(files) == 1
    assert files[0].name == "app.js"


def test_discover_files_nonexistent_dir():
    files = discover_files(Path("/nonexistent/path"))
    assert files == []
