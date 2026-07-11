"""Fingerprint v2 guarantees at the serialized report boundary."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from repomedic.cli import app
from tests.contract.conftest import FIXTURES_ROOT

FINGERPRINT_PATTERN = re.compile(r"RM-[0-9a-f]{10}")
SOURCE_PROJECT = FIXTURES_ROOT / "projects" / "fingerprints"


def _copy_fingerprint_project(tmp_path: Path) -> Path:
    project = tmp_path / "fingerprints"
    shutil.copytree(SOURCE_PROJECT, project)
    return project


def _security_fingerprints(cli_runner, project: Path) -> list[str]:
    result = cli_runner.invoke(
        app,
        ["scan", str(project), "-a", "security", "--no-exec", "-o", "json"],
        env={"PATH": ""},
    )
    payload = json.loads(result.stdout)
    findings = [
        finding
        for analyzer_result in payload["results"]
        for finding in analyzer_result["findings"]
        if finding["code"] == "SEC-001" and finding["file_path"] == "keys.py"
    ]

    assert result.exit_code == 0
    assert len(findings) == 2
    return [finding["fingerprint"] for finding in findings]


def test_fingerprints_are_stable_across_cli_invocations(tmp_path: Path, cli_runner) -> None:
    project = _copy_fingerprint_project(tmp_path)

    assert _security_fingerprints(cli_runner, project) == _security_fingerprints(
        cli_runner, project
    )


def test_fingerprints_survive_line_number_drift(tmp_path: Path, cli_runner) -> None:
    project = _copy_fingerprint_project(tmp_path)
    before = _security_fingerprints(cli_runner, project)

    keys_path = project / "keys.py"
    keys_path.write_text(f"# inserted line\n\n{keys_path.read_text(encoding='utf-8')}", encoding="utf-8")

    assert _security_fingerprints(cli_runner, project) == before


def test_duplicate_occurrences_have_distinct_v2_fingerprints(
    tmp_path: Path, cli_runner
) -> None:
    project = _copy_fingerprint_project(tmp_path)
    fingerprints = _security_fingerprints(cli_runner, project)

    assert len(set(fingerprints)) == 2
    assert all(FINGERPRINT_PATTERN.fullmatch(fingerprint) for fingerprint in fingerprints)
