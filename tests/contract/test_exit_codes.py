"""Public CLI exit-code contract across agent-facing commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from repomedic.cli import app
from repomedic.models_commands import DoctorReport
from tests.contract.conftest import FIXTURES_ROOT

PROJECTS_ROOT = FIXTURES_ROOT / "projects"
SCRIPTS_ROOT = FIXTURES_ROOT / "scripts"
MISSING_PATH = FIXTURES_ROOT / "missing"
BASELINE_OUTPUT_TOKEN = "{baseline_output}"


@dataclass(frozen=True)
class ExitCodeCase:
    command: str
    arguments: tuple[str, ...]
    expected_exit_code: int


EXIT_CODE_CASES = (
    ExitCodeCase(
        "scan",
        ("scan", str(PROJECTS_ROOT / "broken"), "-a", "config", "--no-exec", "-o", "json"),
        0,
    ),
    ExitCodeCase(
        "scan",
        (
            "scan",
            str(PROJECTS_ROOT / "broken"),
            "-a",
            "config",
            "--no-exec",
            "-o",
            "json",
            "--fail-on",
            "error",
        ),
        1,
    ),
    ExitCodeCase("scan", ("scan", str(MISSING_PATH), "-o", "json"), 2),
    ExitCodeCase(
        "sniff",
        ("sniff", str(PROJECTS_ROOT / "clean"), "-a", "config", "--no-exec"),
        0,
    ),
    ExitCodeCase(
        "sniff",
        ("sniff", str(PROJECTS_ROOT / "broken"), "-a", "config", "--no-exec"),
        1,
    ),
    ExitCodeCase("sniff", ("sniff", str(MISSING_PATH)), 2),
    ExitCodeCase("run", ("run", str(SCRIPTS_ROOT / "success.py")), 0),
    ExitCodeCase("run", ("run", str(SCRIPTS_ROOT / "failure.py")), 1),
    ExitCodeCase("run", ("run", str(MISSING_PATH / "script.py")), 2),
    ExitCodeCase("doctor", ("doctor", str(PROJECTS_ROOT / "clean"), "-o", "json"), 0),
    ExitCodeCase(
        "doctor",
        ("doctor", str(PROJECTS_ROOT / "doctor_unhealthy"), "-o", "json"),
        1,
    ),
    ExitCodeCase("doctor", ("doctor", str(MISSING_PATH), "-o", "json"), 2),
    ExitCodeCase(
        "baseline",
        (
            "baseline",
            str(PROJECTS_ROOT / "clean"),
            "--file",
            BASELINE_OUTPUT_TOKEN,
            "-o",
            "json",
        ),
        0,
    ),
    ExitCodeCase("baseline", ("baseline", str(MISSING_PATH), "-o", "json"), 2),
)

EXPECTED_EXIT_CODE_MATRIX = {
    "scan": {0, 1, 2},
    "sniff": {0, 1, 2},
    "run": {0, 1, 2},
    "doctor": {0, 1, 2},
    "baseline": {0, 2},
}


def _resolve_arguments(case: ExitCodeCase, tmp_path: Path) -> list[str]:
    baseline_output = str(tmp_path / "accepted-findings.json")
    return [argument.replace(BASELINE_OUTPUT_TOKEN, baseline_output) for argument in case.arguments]


def test_exit_code_cases_cover_the_supported_matrix() -> None:
    covered: dict[str, set[int]] = {}
    for case in EXIT_CODE_CASES:
        covered.setdefault(case.command, set()).add(case.expected_exit_code)

    assert covered == EXPECTED_EXIT_CODE_MATRIX


@pytest.mark.parametrize("case", EXIT_CODE_CASES, ids=lambda case: f"{case.command}-{case.expected_exit_code}")
def test_cli_exit_code_contract(case, tmp_path: Path, cli_runner, monkeypatch) -> None:
    import repomedic.commands.doctor as doctor_module

    def collect_doctor(target: Path) -> DoctorReport:
        return DoctorReport(target=str(target), healthy=target.name == "clean")

    monkeypatch.setattr(doctor_module, "collect_doctor", collect_doctor)
    result = cli_runner.invoke(
        app,
        _resolve_arguments(case, tmp_path),
        env={"PATH": ""},
    )

    assert result.exit_code == case.expected_exit_code, (
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
