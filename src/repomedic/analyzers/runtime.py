"""Runtime analyzer — execute scripts, capture tracebacks, map to suggestions."""

from __future__ import annotations

import re
import sys

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run

# Map exception types to actionable suggestions
EXCEPTION_SUGGESTIONS: dict[str, str] = {
    "ModuleNotFoundError": "Install the missing module with: pip install <module>",
    "ImportError": "Check that the module is installed and the import path is correct.",
    "FileNotFoundError": "Verify the file path exists. Check for typos or missing files.",
    "PermissionError": "Check file permissions. You may need to chmod or run with appropriate privileges.",
    "KeyError": "The key does not exist in the dictionary. Check for typos or add a default value with .get().",
    "IndexError": "List index is out of range. Check the list length before accessing by index.",
    "TypeError": "Check the types of arguments being passed. A wrong type is being used.",
    "ValueError": "An invalid value was passed. Validate input before processing.",
    "AttributeError": "The object doesn't have the attribute. Check the object type and available attributes.",
    "ZeroDivisionError": "Add a check for zero before dividing.",
    "ConnectionError": "Check network connectivity and the target URL/host.",
    "TimeoutError": "The operation timed out. Increase timeout or check if the service is responsive.",
    "JSONDecodeError": "The input is not valid JSON. Validate the JSON string before parsing.",
    "UnicodeDecodeError": "Specify the correct encoding when reading the file, e.g., encoding='utf-8'.",
}

TRACEBACK_RE = re.compile(
    r'File "([^"]+)", line (\d+).*?\n\s+.*?\n(\w+(?:Error|Exception|Warning)[^\n]*)',
    re.DOTALL,
)


@register
class RuntimeAnalyzer(BaseAnalyzer):
    name = "runtime"
    description = "Execute Python scripts and analyze tracebacks"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return False  # Only run explicitly via CLI 'run' command

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        return AnalyzerResult(analyzer=self.name)

    def analyze_script(self, script_path: str, cwd: str | None = None) -> AnalyzerResult:
        """Run a specific script and analyze its output."""
        result = run(
            [sys.executable, script_path],
            cwd=cwd,
            timeout=30,
        )

        findings: list[Finding] = []

        if result.returncode != 0 and result.stderr:
            findings.extend(self._parse_traceback(result.stderr, script_path))

        if not findings and result.returncode != 0:
            findings.append(
                Finding(
                    category=Category.runtime,
                    severity=Severity.error,
                    code="RUN-001",
                    title="Script failed",
                    description=f"Script exited with code {result.returncode}.",
                    file_path=script_path,
                    suggestion="Check stderr output for details.",
                    metadata={"stderr": result.stderr[:1000], "returncode": result.returncode},
                )
            )

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _parse_traceback(self, stderr: str, script_path: str) -> list[Finding]:
        findings = []

        # Find the last exception line
        lines = stderr.strip().splitlines()
        exc_line = ""
        last_file = script_path
        last_lineno = None

        for i, line in enumerate(lines):
            match = re.match(r'\s*File "([^"]+)", line (\d+)', line)
            if match:
                last_file = match.group(1)
                last_lineno = int(match.group(2))

        # Get the final exception
        for line in reversed(lines):
            line = line.strip()
            if line and not line.startswith("File ") and not line.startswith("Traceback"):
                exc_line = line
                break

        if exc_line:
            exc_type = exc_line.split(":")[0].split(".")[-1].strip()
            suggestion = EXCEPTION_SUGGESTIONS.get(
                exc_type,
                f"Investigate the {exc_type} and fix the root cause.",
            )

            findings.append(
                Finding(
                    category=Category.runtime,
                    severity=Severity.error,
                    code="RUN-002",
                    title=f"Runtime error: {exc_type}",
                    description=exc_line,
                    file_path=last_file,
                    line=last_lineno,
                    suggestion=suggestion,
                    metadata={"traceback": stderr[:2000]},
                )
            )

        return findings
