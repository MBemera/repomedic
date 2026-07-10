"""Runtime analyzer — execute scripts in any supported language and analyze failures."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import ProcessStatus, run

# Interpreter command per file extension. `sys.executable` keeps Python runs
# inside the same environment repomedic was installed into.
INTERPRETERS: dict[str, list[str]] = {
    ".py": [sys.executable],
    ".js": ["node"],
    ".mjs": ["node"],
    ".cjs": ["node"],
    ".sh": ["bash"],
    ".bash": ["bash"],
    ".rb": ["ruby"],
    ".php": ["php"],
    ".pl": ["perl"],
    ".lua": ["lua"],
}

EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".sh": "shell",
    ".bash": "shell",
    ".rb": "ruby",
    ".php": "php",
    ".pl": "perl",
    ".lua": "lua",
}

# Map Python exception types to actionable suggestions
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

# Node.js error hints keyed by a substring of the error message
NODE_SUGGESTIONS: list[tuple[str, str]] = [
    ("Cannot find module", "Install the missing package (npm install <module>) or fix the require/import path."),
    ("is not defined", "The identifier is not defined. Check for typos or missing imports."),
    ("is not a function", "The value is not callable. Check the export/import and the object it comes from."),
    ("ECONNREFUSED", "The target service refused the connection. Check that it is running and the port is correct."),
]

NODE_FRAME_RE = re.compile(r"at .*?\(?((?:/|[A-Za-z]:\\)[^():]+):(\d+):\d+\)?")


@register
class RuntimeAnalyzer(BaseAnalyzer):
    name = "runtime"
    description = "Execute a script (Python, Node, shell, Ruby, PHP, ...) and analyze failures"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return False  # Only run explicitly via CLI 'run' command

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        return AnalyzerResult(analyzer=self.name)

    def analyze_script(
        self,
        script_path: str,
        cwd: str | None = None,
        args: list[str] | None = None,
    ) -> AnalyzerResult:
        """Run a script with the interpreter matching its extension and analyze failures."""
        suffix = Path(script_path).suffix.lower()
        interpreter = INTERPRETERS.get(suffix)
        language = EXTENSION_LANGUAGE.get(suffix)

        if interpreter is None:
            supported = ", ".join(sorted(INTERPRETERS))
            return AnalyzerResult(
                analyzer=self.name,
                error=f"Unsupported script type '{suffix}'. Supported extensions: {supported}",
            )

        # The user explicitly asked to run their own script, so it gets the
        # full environment — unlike scan tools, which run isolated.
        result = run(
            [*interpreter, script_path, *(args or [])],
            cwd=cwd,
            timeout=30,
            env_mode="inherit",
        )

        if result.tool_missing:
            return AnalyzerResult(
                analyzer=self.name,
                error=f"Interpreter not found: {interpreter[0]}. Install it to run {suffix} scripts.",
            )
        if result.status is ProcessStatus.failed_to_start:
            return AnalyzerResult(analyzer=self.name, error=result.stderr)
        if result.status is ProcessStatus.timed_out:
            return AnalyzerResult(
                analyzer=self.name,
                findings=[
                    Finding(
                        category=Category.runtime,
                        severity=Severity.error,
                        code="RUN-001",
                        title="Script timed out",
                        description="Script was killed after running for 30s without finishing.",
                        file_path=script_path,
                        suggestion="Check for infinite loops or blocking calls; profile the slow section.",
                        language=language,
                        metadata={"timeout_seconds": 30},
                    )
                ],
            )

        findings: list[Finding] = []
        if result.returncode != 0 and result.stderr:
            if suffix == ".py":
                findings.extend(self._parse_python_traceback(result.stderr, script_path))
            elif suffix in (".js", ".mjs", ".cjs"):
                findings.extend(self._parse_node_error(result.stderr, script_path))

        if not findings and result.returncode != 0:
            tail = "\n".join(result.stderr.strip().splitlines()[-5:]) or "(no stderr output)"
            findings.append(
                Finding(
                    category=Category.runtime,
                    severity=Severity.error,
                    code="RUN-001",
                    title="Script failed",
                    description=f"Script exited with code {result.returncode}. Last stderr lines:\n{tail}",
                    file_path=script_path,
                    suggestion="Check the stderr output above for details.",
                    language=language,
                    metadata={"stderr": result.stderr[:1000], "returncode": result.returncode},
                )
            )

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _parse_python_traceback(self, stderr: str, script_path: str) -> list[Finding]:
        findings = []

        # Find the last exception line
        lines = stderr.strip().splitlines()
        exc_line = ""
        last_file = script_path
        last_lineno = None

        for line in lines:
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
                    language="python",
                    metadata={"traceback": stderr[:2000]},
                )
            )

        return findings

    def _parse_node_error(self, stderr: str, script_path: str) -> list[Finding]:
        """Parse a Node.js stack trace into a finding."""
        lines = stderr.strip().splitlines()

        # The headline is the first line naming an Error type, e.g. "TypeError: x is not a function"
        exc_line = next(
            (ln.strip() for ln in lines if re.match(r"\w*(?:Error|Exception)\b", ln.strip())),
            "",
        )
        if not exc_line:
            return []

        # First stack frame gives the failing location
        file_path, line_no = script_path, None
        for ln in lines:
            frame = NODE_FRAME_RE.search(ln)
            if frame:
                file_path, line_no = frame.group(1), int(frame.group(2))
                break

        suggestion = next(
            (hint for needle, hint in NODE_SUGGESTIONS if needle in stderr),
            "Investigate the error and fix the root cause.",
        )
        exc_type = exc_line.split(":")[0].strip()

        return [
            Finding(
                category=Category.runtime,
                severity=Severity.error,
                code="RUN-003",
                title=f"Runtime error: {exc_type}",
                description=exc_line,
                file_path=file_path,
                line=line_no,
                suggestion=suggestion,
                language="javascript",
                metadata={"stderr": stderr[:2000]},
            )
        ]
