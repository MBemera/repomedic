"""Analyzer registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repomedic.analyzers.base import BaseAnalyzer

_ANALYZER_CLASSES: list[type[BaseAnalyzer]] = []


def register(cls: type[BaseAnalyzer]) -> type[BaseAnalyzer]:
    """Class decorator to register an analyzer."""
    _ANALYZER_CLASSES.append(cls)
    return cls


def get_all_analyzers() -> list[BaseAnalyzer]:
    """Instantiate and return all registered analyzers."""
    # Import modules to trigger registration
    from repomedic.analyzers import (  # noqa: F401
        config,
        dependencies,
        git,
        golang,
        javascript,
        logs,
        runtime,
        rust,
        security,
        semgrep,
        static,
    )

    return [cls() for cls in _ANALYZER_CLASSES]


def get_analyzer_names() -> list[str]:
    """Return names of all registered analyzers."""
    return [a.name for a in get_all_analyzers()]
