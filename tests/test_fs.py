"""Tests for the file discovery utilities."""

from __future__ import annotations

from pathlib import Path

from repomedic.utils.fs import _is_test_file, discover_files, is_ignored_path


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


def test_read_text_capped(tmp_path):
    from repomedic.utils.fs import read_text_capped

    small = tmp_path / "small.txt"
    small.write_text("hello")
    assert read_text_capped(small) == "hello"

    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 2048)
    assert read_text_capped(big, max_bytes=1024) is None

    assert read_text_capped(tmp_path / "missing.txt") is None


def test_discover_files_excludes_symlink_escaping_root(tmp_path):
    """A symlink pointing outside the scan root must never be discovered."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "credentials"
    secret.write_text("AWS_SECRET=super-sensitive")

    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "creds.py").symlink_to(secret)

    files = discover_files(root, skip_tests=False)
    names = [f.name for f in files]
    assert "app.py" in names
    assert "creds.py" not in names


def test_discover_files_keeps_symlink_inside_root(tmp_path):
    real = tmp_path / "real.py"
    real.write_text("x = 1\n")
    (tmp_path / "alias.py").symlink_to(real)

    files = discover_files(tmp_path, skip_tests=False)
    names = sorted(f.name for f in files)
    assert names == ["alias.py", "real.py"]


def test_discover_files_skips_broken_symlink(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "dangling.py").symlink_to(tmp_path / "missing.py")

    files = discover_files(tmp_path, skip_tests=False)
    assert [f.name for f in files] == ["app.py"]


def test_is_ignored_path_matches_discovery_rules(tmp_path):
    """is_ignored_path must mirror what discover_files would skip."""
    root = tmp_path / "project"
    root.mkdir()

    assert is_ignored_path(Path("src/app.py"), root) is False
    assert is_ignored_path(Path("__pycache__/app.pyc"), root) is True
    assert is_ignored_path(Path("tests/test_app.py"), root) is True
    assert is_ignored_path(Path("src/test_app.py"), root) is True
    assert is_ignored_path(Path("tests/helper.py"), root, skip_tests=False) is False
    assert is_ignored_path(Path("vendored/lib.py"), root, extra_ignore_dirs={"vendored"}) is True


def test_is_ignored_path_absolute_paths(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    assert is_ignored_path(root / "src" / "app.py", root) is False
    assert is_ignored_path(root / "__pycache__" / "app.pyc", root) is True
    assert is_ignored_path(tmp_path / "outside" / "app.py", root) is True


def test_discover_files_does_not_follow_dir_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.py").write_text("x = 1\n")

    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "linked").symlink_to(outside, target_is_directory=True)

    files = discover_files(root, skip_tests=False)
    assert [f.name for f in files] == ["app.py"]
