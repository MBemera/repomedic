"""Tests for `repomedic schema` — JSON Schema export for output payloads."""

from __future__ import annotations

import json

import pytest

from repomedic.cli import app
from tests.cli_runner import create_cli_runner

runner = create_cli_runner()


@pytest.mark.parametrize(
    ("kind", "expected_title"),
    [
        ("report", "ScanReport"),
        ("baseline", "BaselineFile"),
        ("doctor", "DoctorReport"),
        ("explain", "ExplainReport"),
        ("fix", "FixReport"),
        ("analyzers", "AnalyzerList"),
    ],
)
def test_schema_kinds_print_valid_json_schema(kind: str, expected_title: str):
    result = runner.invoke(app, ["schema", "--kind", kind])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["title"] == expected_title
    assert parsed["type"] == "object"


def test_schema_defaults_to_report():
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["title"] == "ScanReport"


def test_schema_rejects_unknown_kind():
    result = runner.invoke(app, ["schema", "--kind", "nonsense"])
    assert result.exit_code == 2


def test_report_schema_validates_a_real_scan(make_project):
    jsonschema = pytest.importorskip("jsonschema")

    from repomedic.core.service import ScanRequest, run_scan
    from repomedic.models import ScanReport

    project = make_project({"app.py": "import os\n"})
    outcome = run_scan(ScanRequest(target=str(project)))
    jsonschema.validate(
        json.loads(outcome.report.model_dump_json()), ScanReport.model_json_schema()
    )
