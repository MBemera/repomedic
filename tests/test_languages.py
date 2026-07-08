"""Tests for the language registry."""

from __future__ import annotations

from pathlib import Path

from repomedic.core.languages import (
    detect_languages,
    fence_for_path,
    language_for_path,
    spec_for,
    verify_commands_for,
)


def test_language_for_extension():
    assert language_for_path("src/app.py") == "python"
    assert language_for_path("web/index.tsx") == "typescript"
    assert language_for_path("main.go") == "go"
    assert language_for_path("lib.rs") == "rust"
    assert language_for_path("script.sh") == "shell"
    assert language_for_path("App.java") == "java"
    assert language_for_path("main.zig") == "zig"
    assert language_for_path("query.sql") == "sql"


def test_language_for_special_filenames():
    assert language_for_path("Dockerfile") == "dockerfile"
    assert language_for_path("Makefile") == "make"


def test_unknown_extension_returns_none():
    assert language_for_path("data.parquet") is None
    assert language_for_path("photo.png") is None


def test_fence_hints():
    assert fence_for_path("app.py") == "python"
    assert fence_for_path("script.sh") == "bash"
    assert fence_for_path("config.yaml") == "yaml"
    assert fence_for_path("settings.json") == "json"
    assert fence_for_path("unknown.xyz") == ""


def test_detect_languages_counts_and_sorts():
    files = [
        Path("a.py"),
        Path("b.py"),
        Path("c.py"),
        Path("x.go"),
        Path("README.txt"),
    ]
    counts = detect_languages(files)
    assert counts == {"python": 3, "go": 1}
    assert list(counts)[0] == "python"  # dominant language first


def test_verify_commands():
    cmds = verify_commands_for(["python", "go"])
    assert "ruff check ." in cmds
    assert "go vet ./..." in cmds
    assert verify_commands_for(["nonexistent-lang"]) == []


def test_spec_lookup():
    spec = spec_for("python")
    assert spec is not None
    assert ".py" in spec.extensions
    assert spec_for("cobol-2200") is None
