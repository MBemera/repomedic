"""SARIF 2.1.0 output formatter.

SARIF is the interchange format GitHub code scanning, VS Code SARIF
viewers, and most CI security dashboards consume. One scan maps to one
``run``; each unique finding code becomes a reporting rule and each
finding becomes a result carrying ``partialFingerprints`` keyed by the
v2 content-hash fingerprint — line-independent, so code-scanning alert
dedup survives commits that shift lines.

All text lands in JSON string fields, so untrusted repo text cannot
break the document structure (unlike markdown, no fencing is needed).
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import PurePosixPath

from repomedic.models import Finding, ScanReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
FINGERPRINT_KEY = "repomedicFingerprint/v2"
INFORMATION_URI = "https://github.com/MBemera/repomedic"

_LEVEL_FOR_SEVERITY = {"error": "error", "warning": "warning", "info": "note"}


def _tool_version() -> str:
    try:
        return version("repomedic")
    except PackageNotFoundError:
        return "0.0.0"


def to_sarif(report: ScanReport) -> dict:
    """Convert a ScanReport to a SARIF 2.1.0 log (single run)."""
    findings = report.findings
    rules, rule_index_for_code = _build_rules(findings)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoMedic",
                        "informationUri": INFORMATION_URI,
                        "semanticVersion": _tool_version(),
                        "rules": rules,
                    }
                },
                "results": [
                    _result_for(f, rule_index_for_code[f.code]) for f in findings
                ],
                "invocations": [_invocation_for(report)],
            }
        ],
    }


def print_sarif(report: ScanReport) -> str:
    """Serialize report to a SARIF JSON string."""
    import json

    return json.dumps(to_sarif(report), indent=2, ensure_ascii=False)


def _build_rules(findings: list[Finding]) -> tuple[list[dict], dict[str, int]]:
    """One reporting rule per unique finding code, in first-seen order."""
    rules: list[dict] = []
    index_for_code: dict[str, int] = {}
    for finding in findings:
        if finding.code in index_for_code:
            continue
        index_for_code[finding.code] = len(rules)
        rules.append(
            {
                "id": finding.code,
                "shortDescription": {"text": finding.title},
                "defaultConfiguration": {
                    "level": _LEVEL_FOR_SEVERITY[finding.severity.value]
                },
                "properties": {"category": finding.category.value},
            }
        )
    return rules, index_for_code


def _result_for(finding: Finding, rule_index: int) -> dict:
    message = finding.description
    if finding.suggestion:
        message = f"{message}\n\nFix: {finding.suggestion}"

    result: dict = {
        "ruleId": finding.code,
        "ruleIndex": rule_index,
        "level": _LEVEL_FOR_SEVERITY[finding.severity.value],
        "message": {"text": message},
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
    }
    masked_match = finding.metadata.get("match_masked")
    if isinstance(masked_match, str) and masked_match:
        result["properties"] = {"repomedicMaskedMatch": masked_match}
    if finding.file_path:
        physical: dict = {
            "artifactLocation": {"uri": str(PurePosixPath(finding.file_path))}
        }
        if finding.line and finding.line >= 1:
            region: dict = {"startLine": finding.line}
            if finding.column and finding.column >= 1:
                region["startColumn"] = finding.column
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    return result


def _invocation_for(report: ScanReport) -> dict:
    """Carry analyzer failures and skipped checks as execution notifications."""
    notifications: list[dict] = []
    for analyzer_result in report.results:
        if analyzer_result.error:
            notifications.append(
                {
                    "level": "error",
                    "message": {
                        "text": f"Analyzer '{analyzer_result.analyzer}' failed: {analyzer_result.error}"
                    },
                }
            )
        for skipped in analyzer_result.skipped_checks:
            notifications.append(
                {
                    "level": "note",
                    "message": {
                        "text": f"Analyzer '{analyzer_result.analyzer}' skipped: {skipped}"
                    },
                }
            )
    invocation: dict = {"executionSuccessful": True}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return invocation
