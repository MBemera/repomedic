"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def broken_imports_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "broken_imports"


@pytest.fixture
def make_project(tmp_path: Path):
    """Factory fixture to create test project directories."""

    def _make(files: dict[str, str]) -> Path:
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return tmp_path

    return _make
