"""Tests for the .repomedic.toml / [tool.repomedic] config loader."""

from __future__ import annotations

from repomedic.core.config import load_config


def test_no_config_returns_defaults(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg.analyzers is None
    assert cfg.exclude == []
    assert cfg.min_severity is None
    assert cfg.max_findings is None
    assert cfg.fail_on is None
    assert cfg.include_tests is False


def test_standalone_config_file(tmp_path):
    (tmp_path / ".repomedic.toml").write_text(
        'analyzers = ["static", "GIT"]\n'
        'exclude = ["migrations", "vendor"]\n'
        'min_severity = "warning"\n'
        "max_findings = 25\n"
        'fail_on = "error"\n'
        "include_tests = true\n"
    )
    cfg = load_config(tmp_path)
    assert cfg.analyzers == ["static", "git"]  # normalized to lowercase
    assert cfg.exclude == ["migrations", "vendor"]
    assert cfg.min_severity == "warning"
    assert cfg.max_findings == 25
    assert cfg.fail_on == "error"
    assert cfg.include_tests is True


def test_pyproject_tool_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n\n[tool.repomedic]\nmin_severity = "error"\nexclude = ["gen"]\n'
    )
    cfg = load_config(tmp_path)
    assert cfg.min_severity == "error"
    assert cfg.exclude == ["gen"]


def test_standalone_wins_over_pyproject(tmp_path):
    (tmp_path / ".repomedic.toml").write_text('min_severity = "warning"\n')
    (tmp_path / "pyproject.toml").write_text('[tool.repomedic]\nmin_severity = "error"\n')
    cfg = load_config(tmp_path)
    assert cfg.min_severity == "warning"


def test_invalid_values_ignored(tmp_path):
    (tmp_path / ".repomedic.toml").write_text(
        'min_severity = "catastrophic"\n'
        "max_findings = -5\n"
        'fail_on = "sometimes"\n'
        'analyzers = "static"\n'  # wrong type: string, not list
    )
    cfg = load_config(tmp_path)
    assert cfg.min_severity is None
    assert cfg.max_findings is None
    assert cfg.fail_on is None
    assert cfg.analyzers is None


def test_broken_toml_ignored(tmp_path):
    (tmp_path / ".repomedic.toml").write_text("this is {{{ not toml\n")
    cfg = load_config(tmp_path)
    assert cfg.analyzers is None
