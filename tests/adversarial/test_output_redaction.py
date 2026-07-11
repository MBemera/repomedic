"""Secret material must not survive any agent-facing serialization."""

from __future__ import annotations

import pytest

import repomedic.analyzers.security as security_module
from repomedic.core.service import ScanRequest, run_scan
from repomedic.output.json_output import print_json
from repomedic.output.markdown_output import render_fix_report
from repomedic.output.sarif_output import print_sarif
from repomedic.utils.process import ProcessResult, ProcessStatus
from repomedic.utils.redact import mask_secret
from tests.adversarial.payloads import SECRET_VALUE

pytestmark = pytest.mark.adversarial


def test_secret_is_masked_in_json_markdown_and_sarif(
    make_project,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = make_project(
        {"config.py": f'aws_access_key = "{SECRET_VALUE}"\n'}
    )
    monkeypatch.setattr(
        security_module,
        "run_json_tool",
        lambda *args, **kwargs: (
            None,
            ProcessResult(
                status=ProcessStatus.not_found,
                returncode=None,
                stdout="",
                stderr="gitleaks unavailable",
            ),
        ),
    )

    report = run_scan(
        ScanRequest(target=str(project), analyzers=["security"])
    ).report
    expected_mask = mask_secret(SECRET_VALUE).encode()
    raw_secret = SECRET_VALUE.encode()
    serialized_outputs = {
        "json": print_json(report).encode(),
        "markdown": render_fix_report(report, include_snippets=True).encode(),
        "sarif": print_sarif(report).encode(),
    }

    assert any(finding.code == "SEC-001" for finding in report.findings)
    for output_name, output_bytes in serialized_outputs.items():
        assert raw_secret not in output_bytes, f"secret leaked in {output_name}"
    outputs_missing_mask = [
        output_name
        for output_name, output_bytes in serialized_outputs.items()
        if expected_mask not in output_bytes
    ]
    assert not outputs_missing_mask, (
        f"masked secret missing from: {', '.join(outputs_missing_mask)}"
    )

    assert b"snippet withheld" in serialized_outputs["markdown"]
