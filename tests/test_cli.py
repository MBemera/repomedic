"""End-to-end CLI tests via typer's CliRunner — agent-facing contract tests."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from repomedic.cli import app

runner = CliRunner()


@pytest.fixture
def broken_project(make_project):
    return make_project({
        "app.py": "def broken(:\n    pass\n",
        "README.md": "# demo\n",
        "LICENSE": "MIT\n",
    })


@pytest.fixture
def clean_project(make_project):
    return make_project({
        "app.py": "x = 1\n",
        "README.md": "# demo\n",
        "LICENSE": "MIT\n",
        ".gitignore": "*.pyc\n",
    })


def test_scan_json_stdout_is_pure_json(broken_project):
    result = runner.invoke(app, [str(broken_project), "--output", "json"])
    data = json.loads(result.stdout)  # raises if any non-JSON noise leaked
    assert data["schema_version"] == 2
    assert data["summary"]["errors"] >= 1
    assert "python" in data["languages"]


def test_scan_default_exit_zero_even_with_findings(broken_project):
    result = runner.invoke(app, [str(broken_project), "--output", "json"])
    assert result.exit_code == 0  # default fail_on=never


def test_scan_fail_on_error_broken(broken_project):
    result = runner.invoke(app, [str(broken_project), "-o", "json", "--fail-on", "error"])
    assert result.exit_code == 1


def test_scan_fail_on_error_clean(clean_project):
    result = runner.invoke(app, [str(clean_project), "-o", "json", "--fail-on", "error"])
    assert result.exit_code == 0


def test_sniff_prints_markdown_and_fails_on_error(broken_project):
    result = runner.invoke(app, ["sniff", str(broken_project)])
    assert result.exit_code == 1
    assert result.stdout.startswith("---\ntool: repomedic")
    assert "## Findings by File" in result.stdout


def test_sniff_clean_project_exits_zero(clean_project):
    result = runner.invoke(app, ["sniff", str(clean_project)])
    assert result.exit_code == 0


def test_explicit_scan_subcommand(broken_project):
    result = runner.invoke(app, ["scan", str(broken_project), "-o", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["errors"] >= 1


def test_bad_target_exits_two():
    result = runner.invoke(app, ["/nonexistent/path/xyz", "-o", "json"])
    assert result.exit_code == 2


def test_unknown_analyzer_exits_two(clean_project):
    result = runner.invoke(app, [str(clean_project), "-a", "bogus"])
    assert result.exit_code == 2


def test_invalid_fail_on_exits_two(clean_project):
    result = runner.invoke(app, [str(clean_project), "--fail-on", "sometimes"])
    assert result.exit_code == 2


def test_max_findings_truncates(broken_project):
    result = runner.invoke(
        app, [str(broken_project), "-o", "json", "--max-findings", "1"]
    )
    data = json.loads(result.stdout)
    shown = sum(len(r["findings"]) for r in data["results"])
    assert shown == 1
    assert data["summary"]["omitted_findings"] >= 1


def test_repo_config_applies(make_project):
    project = make_project({
        "app.py": "def broken(:\n    pass\n",
        ".repomedic.toml": 'fail_on = "error"\n',
    })
    result = runner.invoke(app, [str(project), "-o", "json"])
    assert result.exit_code == 1  # fail_on from config


def test_agents_command_prints_guide():
    result = runner.invoke(app, ["agents"])
    assert result.exit_code == 0
    assert "repomedic sniff" in result.stdout
    assert "Exit codes" in result.stdout


def test_list_analyzers_json():
    result = runner.invoke(app, ["list-analyzers", "-o", "json"])
    names = {a["name"] for a in json.loads(result.stdout)}
    assert {"static", "git", "security", "shell", "hygiene"} <= names


def test_doctor_json(clean_project):
    result = runner.invoke(app, ["doctor", str(clean_project), "-o", "json"])
    data = json.loads(result.stdout)
    assert "checks" in data
    assert "healthy" in data


def test_explain_markdown(clean_project):
    result = runner.invoke(app, ["explain", str(clean_project), "-o", "markdown"])
    assert result.exit_code == 0
    assert "# Project Brief" in result.stdout
    assert "python" in result.stdout


def test_fix_dry_run_writes_nothing(make_project):
    project = make_project({"app.py": "x = 1\n"})
    result = runner.invoke(app, ["fix", str(project), "--dry-run", "-o", "json"])
    rows = json.loads(result.stdout)
    gitignore_row = next(r for r in rows if r["action"] == ".gitignore")
    assert gitignore_row["status"] == "WOULD FIX"
    assert not (project / ".gitignore").exists()


def test_run_reports_runtime_error(tmp_path):
    script = tmp_path / "boom.py"
    script.write_text("raise ValueError('nope')\n")
    result = runner.invoke(app, ["run", str(script)])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    findings = data["results"][0]["findings"]
    assert any("ValueError" in f["title"] for f in findings)
