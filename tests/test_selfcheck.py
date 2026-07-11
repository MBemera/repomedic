"""Tests for the installed-package ``repomedic selfcheck`` command."""

from __future__ import annotations

import json
import sys

import pytest

from repomedic.cli import app
from repomedic.commands import selfcheck
from repomedic.models_commands import SelfcheckCheck, SelfcheckReport
from repomedic.utils.process import ProcessResult, ProcessStatus
from tests.cli_runner import create_cli_runner

runner = create_cli_runner()

EXPECTED_CHECK_NAMES = [
    "import-integrity",
    "env-basics",
    "pipeline-roundtrip",
    "schema-self-validation",
    "render-integrity",
    "extras-status",
]


def test_collect_selfcheck_passes_required_checks() -> None:
    report = selfcheck.collect_selfcheck()

    assert report.schema_version == 1
    assert report.healthy is True
    assert [check.name for check in report.checks] == EXPECTED_CHECK_NAMES
    assert [check.status for check in report.checks[:-1]] == ["PASS"] * 5
    assert report.checks[-1].status == "INFO"


def test_environment_check_uses_isolated_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], str]] = []

    def fake_run(command: list[str], **options: object) -> ProcessResult:
        calls.append((command, str(options.get("env_mode"))))
        return ProcessResult(ProcessStatus.ok, 0, "tool version 1\n", "")

    monkeypatch.setattr(selfcheck, "run", fake_run)

    assert "python=tool version 1" in selfcheck._check_env_basics()
    assert len(calls) == 2
    assert all(env_mode == "isolated" for _, env_mode in calls)


def test_pipeline_and_render_canaries_pass() -> None:
    pipeline_detail = selfcheck._check_pipeline_roundtrip()
    render_detail = selfcheck._check_render_integrity()

    assert "CFG-010" in pipeline_detail
    assert "LOG-001" in pipeline_detail
    assert "front matter" in render_detail


def test_collect_selfcheck_converts_exceptions_to_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_import_check() -> str:
        raise RuntimeError("broken registry")

    monkeypatch.setattr(selfcheck, "_check_import_integrity", fail_import_check)

    report = selfcheck.collect_selfcheck()

    failed = report.checks[0]
    assert report.healthy is False
    assert failed.status == "FAIL"
    assert "broken registry" in failed.detail


def test_schema_check_fails_closed_without_jsonschema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "jsonschema.validators", None)
    for check_name in (
        "_check_import_integrity",
        "_check_env_basics",
        "_check_pipeline_roundtrip",
        "_check_render_integrity",
    ):
        monkeypatch.setattr(selfcheck, check_name, lambda: "passed")

    report = selfcheck.collect_selfcheck()
    schema_check = next(
        check for check in report.checks if check.name == "schema-self-validation"
    )

    assert report.healthy is False
    assert schema_check.status == "FAIL"
    assert "jsonschema" in schema_check.detail


@pytest.mark.parametrize(("healthy", "exit_code"), [(True, 0), (False, 1)])
def test_selfcheck_json_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    healthy: bool,
    exit_code: int,
) -> None:
    status = "PASS" if healthy else "FAIL"
    report = SelfcheckReport(
        healthy=healthy,
        checks=[SelfcheckCheck(name="test", status=status, detail="result")],
    )
    monkeypatch.setattr(selfcheck, "collect_selfcheck", lambda: report)

    result = runner.invoke(app, ["selfcheck", "-o", "json"])

    assert result.exit_code == exit_code
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["healthy"] is healthy


def test_selfcheck_rejects_unknown_output() -> None:
    result = runner.invoke(app, ["selfcheck", "-o", "yaml"])

    assert result.exit_code == 2
    assert "invalid --output" in result.stderr


def test_selfcheck_schema_is_exported() -> None:
    result = runner.invoke(app, ["schema", "--kind", "selfcheck"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["title"] == "SelfcheckReport"
