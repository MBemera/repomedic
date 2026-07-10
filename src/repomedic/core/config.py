"""Project configuration — `.repomedic.toml` or `[tool.repomedic]` in pyproject.toml.

CLI flags always win; config supplies defaults so a repo can pin its scan
behavior once and every agent/human invocation picks it up.

Example `.repomedic.toml`:

    analyzers = ["static", "git", "security"]
    exclude = ["migrations", "vendor"]
    min_severity = "warning"
    max_findings = 50
    fail_on = "error"
    include_tests = false
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("repomedic")

CONFIG_FILENAME = ".repomedic.toml"

VALID_SEVERITIES = {"error", "warning", "info"}
VALID_FAIL_ON = {"error", "warning", "any", "never"}


@dataclass
class RepomedicConfig:
    """Resolved scan configuration for a target project."""

    analyzers: list[str] | None = None
    exclude: list[str] = field(default_factory=list)
    min_severity: str | None = None
    max_findings: int | None = None
    fail_on: str | None = None
    include_tests: bool = False
    analyzer_timeout: float | None = None


def load_config(target: Path) -> RepomedicConfig:
    """Load config from `.repomedic.toml`, falling back to `[tool.repomedic]`."""
    data = _read_config_table(target)
    if not data:
        return RepomedicConfig()

    cfg = RepomedicConfig()

    analyzers = data.get("analyzers")
    if isinstance(analyzers, list) and all(isinstance(a, str) for a in analyzers):
        cfg.analyzers = [a.strip().lower() for a in analyzers]

    exclude = data.get("exclude")
    if isinstance(exclude, list) and all(isinstance(e, str) for e in exclude):
        cfg.exclude = exclude

    min_severity = data.get("min_severity")
    if isinstance(min_severity, str) and min_severity in VALID_SEVERITIES:
        cfg.min_severity = min_severity

    max_findings = data.get("max_findings")
    if isinstance(max_findings, int) and max_findings >= 0:
        cfg.max_findings = max_findings

    fail_on = data.get("fail_on")
    if isinstance(fail_on, str) and fail_on in VALID_FAIL_ON:
        cfg.fail_on = fail_on

    include_tests = data.get("include_tests")
    if isinstance(include_tests, bool):
        cfg.include_tests = include_tests

    analyzer_timeout = data.get("analyzer_timeout")
    if isinstance(analyzer_timeout, (int, float)) and not isinstance(analyzer_timeout, bool) and analyzer_timeout >= 0:
        cfg.analyzer_timeout = float(analyzer_timeout)

    return cfg


def _read_config_table(target: Path) -> dict:
    """Return the raw config mapping from disk, or {} when absent/invalid."""
    standalone = target / CONFIG_FILENAME
    if standalone.is_file():
        try:
            return tomllib.loads(standalone.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            logger.warning("Ignoring invalid %s: %s", CONFIG_FILENAME, exc)
            return {}

    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            table = data.get("tool", {}).get("repomedic", {})
            return table if isinstance(table, dict) else {}
        except (tomllib.TOMLDecodeError, OSError) as exc:
            logger.warning("Ignoring invalid pyproject.toml for config: %s", exc)
            return {}

    return {}
