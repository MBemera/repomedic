"""Installed-package integrity checks for ``repomedic selfcheck``."""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Callable

from pydantic import BaseModel
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from repomedic.analyzers import get_all_analyzers
from repomedic.core.service import ScanRequest, run_scan
from repomedic.models import (
    AnalyzerResult,
    Category,
    Finding,
    ScanReport,
    Severity,
)
from repomedic.models_commands import SelfcheckCheck, SelfcheckReport
from repomedic.output.markdown_output import render_fix_report
from repomedic.utils.process import ProcessResult, run

EXPECTED_ANALYZER_MODULES = (
    "config",
    "dependencies",
    "git",
    "golang",
    "hygiene",
    "javascript",
    "logs",
    "runtime",
    "rust",
    "security",
    "semgrep",
    "shell",
    "static",
)

EXPECTED_ANALYZER_NAMES = frozenset(
    {
        "config",
        "dependencies",
        "git",
        "go",
        "hygiene",
        "javascript",
        "logs",
        "runtime",
        "rust",
        "security",
        "semgrep",
        "shell",
        "static",
    }
)

OPTIONAL_EXTRAS = (
    ("tools", ("semgrep", "bandit")),
    ("debug", ("debugpy",)),
    ("mcp", ("mcp",)),
)

SELFCHECK_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "selfcheck"
RENDER_CANARY = "REPOMEDIC_SELFCHECK_CANARY"

CheckFunction = Callable[[], str]


class SelfcheckFailure(RuntimeError):
    """A required self-check detected an integrity problem."""


def collect_selfcheck() -> SelfcheckReport:
    """Run every self-check and return a stable, machine-readable report."""
    required_checks: tuple[tuple[str, CheckFunction], ...] = (
        ("import-integrity", _check_import_integrity),
        ("env-basics", _check_env_basics),
        ("pipeline-roundtrip", _check_pipeline_roundtrip),
        ("schema-self-validation", _check_schema_self_validation),
        ("render-integrity", _check_render_integrity),
    )
    checks = [_run_required_check(name, check) for name, check in required_checks]
    checks.append(_collect_extras_status())
    return SelfcheckReport(
        healthy=all(check.status != "FAIL" for check in checks),
        checks=checks,
    )


def _run_required_check(name: str, check: CheckFunction) -> SelfcheckCheck:
    try:
        detail = check()
    except Exception as exc:
        error = _single_line(f"{type(exc).__name__}: {exc}")
        return SelfcheckCheck(name=name, status="FAIL", detail=error)
    return SelfcheckCheck(name=name, status="PASS", detail=_single_line(detail))


def _single_line(value: str, max_length: int = 500) -> str:
    normalized = " ".join(str(value).split())
    if len(normalized) <= max_length:
        return normalized
    return normalized[: max_length - 1] + "…"


def _check_import_integrity() -> str:
    import_failures: list[str] = []
    for module_name in EXPECTED_ANALYZER_MODULES:
        qualified_name = f"repomedic.analyzers.{module_name}"
        try:
            importlib.import_module(qualified_name)
        except Exception as exc:
            import_failures.append(f"{module_name} ({type(exc).__name__})")

    if import_failures:
        raise SelfcheckFailure(f"analyzer imports failed: {', '.join(import_failures)}")

    names = [analyzer.name for analyzer in get_all_analyzers()]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    missing = sorted(EXPECTED_ANALYZER_NAMES - set(names))
    unexpected = sorted(set(names) - EXPECTED_ANALYZER_NAMES)
    if duplicates or missing or unexpected or len(names) != len(EXPECTED_ANALYZER_NAMES):
        raise SelfcheckFailure(
            "analyzer registry mismatch; "
            f"count={len(names)}, duplicates={duplicates}, missing={missing}, "
            f"unexpected={unexpected}"
        )
    return f"{len(names)} analyzers imported with unique names"


def _check_env_basics() -> str:
    commands = (
        ("python", [sys.executable, "--version"]),
        ("git", ["git", "--version"]),
    )
    failures: list[str] = []
    versions: list[str] = []
    for name, command in commands:
        result = run(command, timeout=10, env_mode="isolated")
        if not result.ok:
            failures.append(f"{name} ({_process_failure(result)})")
            continue
        version = _first_output_line(result) or "available"
        versions.append(f"{name}={version}")

    if failures:
        raise SelfcheckFailure(f"required commands unavailable: {', '.join(failures)}")
    return "; ".join(versions)


def _process_failure(result: ProcessResult) -> str:
    if result.returncode is not None:
        return f"exit {result.returncode}"
    return result.status.value


def _first_output_line(result: ProcessResult) -> str:
    output = result.stdout.strip() or result.stderr.strip()
    if not output:
        return ""
    return _single_line(output.splitlines()[0], max_length=120)


def _check_pipeline_roundtrip() -> str:
    manifest = _load_fixture_manifest()
    fixture_project = SELFCHECK_DATA_DIR / "project"
    if not fixture_project.is_dir():
        raise SelfcheckFailure(f"bundled fixture missing: {fixture_project}")

    outcome = run_scan(
        ScanRequest(
            target=str(fixture_project),
            analyzers=manifest["analyzers"],
            max_findings=0,
            fail_on="never",
            allow_exec=False,
            use_baseline=False,
        )
    )
    try:
        codes = {finding.code for finding in outcome.report.findings}
        analyzer_errors = [
            f"{result.analyzer}: {result.error}"
            for result in outcome.report.results
            if result.error
        ]
    finally:
        outcome.cleanup()

    expected = set(manifest["expected_codes"])
    forbidden = set(manifest["forbidden_codes"])
    missing = sorted(expected - codes)
    present_forbidden = sorted(forbidden & codes)
    if missing or present_forbidden or analyzer_errors:
        raise SelfcheckFailure(
            f"missing={missing}, forbidden_present={present_forbidden}, "
            f"analyzer_errors={analyzer_errors}"
        )
    return f"expected codes present ({', '.join(sorted(expected))}); forbidden codes absent"


def _load_fixture_manifest() -> dict[str, list[str]]:
    manifest_path = SELFCHECK_DATA_DIR / "manifest.json"
    try:
        raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SelfcheckFailure(f"invalid bundled fixture manifest: {exc}") from exc

    manifest: dict[str, list[str]] = {}
    for field in ("analyzers", "expected_codes", "forbidden_codes"):
        value = raw_manifest.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise SelfcheckFailure(f"fixture manifest field '{field}' must be a string list")
        manifest[field] = value
    if not manifest["analyzers"] or not manifest["expected_codes"]:
        raise SelfcheckFailure("fixture manifest requires analyzers and expected_codes")
    return manifest


def _check_schema_self_validation() -> str:
    try:
        from jsonschema.validators import validator_for  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SelfcheckFailure(
            "required runtime dependency 'jsonschema' is unavailable"
        ) from exc

    schemas = {
        model.__name__: model.model_json_schema() for model in _schema_models()
    }
    for name, schema in schemas.items():
        try:
            validator_for(schema).check_schema(schema)
        except Exception as exc:
            raise SelfcheckFailure(f"{name} schema is invalid: {exc}") from exc
    return f"{len(schemas)} schemas validated against their declared meta-schema"


def _schema_models() -> tuple[type[BaseModel], ...]:
    from repomedic.core.baseline import BaselineFile
    from repomedic.models_commands import (
        AnalyzerList,
        DoctorReport,
        ExplainReport,
        FixReport,
    )

    return (
        ScanReport,
        BaselineFile,
        DoctorReport,
        ExplainReport,
        FixReport,
        AnalyzerList,
        SelfcheckReport,
    )


def _check_render_integrity() -> str:
    target_canary = "selfcheck-target\n---\nforged: true"
    payload = f"```\n# {RENDER_CANARY}\n---"
    finding = Finding(
        category=Category.static_analysis,
        severity=Severity.error,
        code="SELFCHECK-001",
        title="Render canary",
        description=payload,
    )
    report = ScanReport(
        target=target_canary,
        results=[AnalyzerResult(analyzer="selfcheck", findings=[finding])],
    )
    report.build_summary()
    rendered = render_fix_report(report, include_snippets=False)

    front_matter = _parse_front_matter(rendered)
    if front_matter.get("target") != target_canary or "forged" in front_matter:
        raise SelfcheckFailure("front matter did not preserve the escaped target")
    _assert_canary_is_fenced(rendered, payload)
    return "canary payload fenced and YAML front matter parsed safely"


def _parse_front_matter(rendered: str) -> dict:
    import yaml  # type: ignore[import-untyped]

    lines = rendered.splitlines()
    if not lines or lines[0] != "---":
        raise SelfcheckFailure("rendered report has no front matter")
    try:
        closing_index = lines.index("---", 1)
        parsed = yaml.safe_load("\n".join(lines[1:closing_index]))
    except (ValueError, yaml.YAMLError) as exc:
        raise SelfcheckFailure(f"front matter did not parse: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SelfcheckFailure("front matter did not parse to a mapping")
    return parsed


def _assert_canary_is_fenced(rendered: str, payload: str) -> None:
    lines = rendered.splitlines()
    marker_line = f"# {RENDER_CANARY}"
    try:
        marker_index = lines.index(marker_line)
    except ValueError as exc:
        raise SelfcheckFailure("render canary is missing") from exc

    opening_index, fence = _find_opening_fence(lines, marker_index)
    try:
        closing_index = lines.index(fence, marker_index + 1)
    except ValueError as exc:
        raise SelfcheckFailure("render canary fence is not closed") from exc

    payload_lines = payload.splitlines()
    if lines[opening_index + 1 : closing_index] != payload_lines:
        raise SelfcheckFailure("render canary escaped its containing fence")
    longest_payload_fence = max(
        (len(match.group()) for match in re.finditer(r"`+", payload)),
        default=0,
    )
    if len(fence) <= longest_payload_fence:
        raise SelfcheckFailure("render canary fence is not strictly longer than its payload")


def _find_opening_fence(lines: list[str], marker_index: int) -> tuple[int, str]:
    for index in range(marker_index - 1, -1, -1):
        match = re.fullmatch(r"(`{3,})text", lines[index])
        if match:
            return index, match.group(1)
    raise SelfcheckFailure("render canary has no opening fence")


def _collect_extras_status() -> SelfcheckCheck:
    statuses: list[str] = []
    for extra_name, module_names in OPTIONAL_EXTRAS:
        missing = [name for name in module_names if not _module_available(name)]
        if missing:
            statuses.append(f"{extra_name}=missing {','.join(missing)}")
        else:
            statuses.append(f"{extra_name}=available")
    return SelfcheckCheck(
        name="extras-status",
        status="INFO",
        detail="; ".join(statuses),
    )


def _module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def render_selfcheck(report: SelfcheckReport, out: Console | None = None) -> None:
    """Render a human-readable self-check table."""
    out = out or Console()
    color = "green" if report.healthy else "red"
    summary = "All required checks passed" if report.healthy else "Required checks failed"
    out.print(Panel(f"[{color}]{summary}[/]", title="repomedic selfcheck"))

    table = Table(show_header=True, header_style="bold", border_style=color)
    table.add_column("Check", style="cyan")
    table.add_column("Status", width=8)
    table.add_column("Detail")
    status_styles = {"PASS": "green", "FAIL": "red", "INFO": "blue"}
    for check in report.checks:
        style = status_styles[check.status]
        table.add_row(
            escape(check.name),
            f"[{style}]{check.status}[/]",
            escape(check.detail),
        )
    out.print(table)
