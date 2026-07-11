"""Committed report-schema drift and live-output validation."""

from __future__ import annotations

import json

import pytest

from tests.contract.conftest import CONTRACT_ROOT, FIXTURES_ROOT

SCHEMA_SNAPSHOT = CONTRACT_ROOT / "snapshots" / "report.schema.json"
BROKEN_PROJECT = FIXTURES_ROOT / "projects" / "broken"


def _load_schema_snapshot() -> dict:
    return json.loads(SCHEMA_SNAPSHOT.read_text(encoding="utf-8"))


def test_exported_report_schema_matches_committed_snapshot(run_cli_process) -> None:
    result = run_cli_process(["schema", "--kind", "report"])

    assert result.returncode == 0
    assert json.loads(result.stdout) == _load_schema_snapshot()
    assert result.stderr == ""


def test_live_json_output_validates_against_committed_schema(run_cli_process) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_schema_snapshot()
    result = run_cli_process(
        [
            "scan",
            str(BROKEN_PROJECT),
            "-a",
            "config",
            "--no-exec",
            "-o",
            "json",
        ]
    )
    payload = json.loads(result.stdout)

    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(payload)
    assert result.returncode == 0
    assert payload["schema_version"] == 3
