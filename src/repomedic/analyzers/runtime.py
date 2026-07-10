"""Runtime analyzer — execute scripts in any supported language and analyze failures."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.debug.session import (
    CaptureBounds,
    CapturedFrame,
    DebugCapture,
    DebugCaptureOutcome,
    DebugCaptureStatus,
    capture_python_crash_outcome,
)
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import ProcessResult, ProcessStatus, run
from repomedic.utils.redact import redact_sensitive_text

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
    (
        "Cannot find module",
        "Install the missing package (npm install <module>) or fix the require/import path.",
    ),
    (
        "is not defined",
        "The identifier is not defined. Check for typos or missing imports.",
    ),
    (
        "is not a function",
        "The value is not callable. Check the export/import and the object it comes from.",
    ),
    (
        "ECONNREFUSED",
        "The target service refused the connection. Check that it is running and the port is correct.",
    ),
]

NODE_FRAME_RE = re.compile(r"at .*?\(?((?:/|[A-Za-z]:\\)[^():]+):(\d+):\d+\)?")


@register
class RuntimeAnalyzer(BaseAnalyzer):
    name = "runtime"
    description = (
        "Execute a script (Python, Node, shell, Ruby, PHP, ...) and analyze failures"
    )

    def is_applicable(self, ctx: ScanContext) -> bool:
        return False  # Only run explicitly via CLI 'run' command

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        return AnalyzerResult(analyzer=self.name)

    def analyze_script(
        self,
        script_path: str,
        cwd: str | None = None,
        args: list[str] | None = None,
        *,
        debug: bool = False,
        bounds: CaptureBounds | None = None,
        timeout: int = 30,
    ) -> AnalyzerResult:
        """Run a script with the interpreter matching its extension and analyze failures."""
        if timeout <= 0:
            return AnalyzerResult(analyzer=self.name, error="Timeout must be positive.")

        suffix = Path(script_path).suffix.lower()
        configuration = self._script_configuration(suffix)
        if configuration is None:
            return self._unsupported_script_result(suffix)
        interpreter, language = configuration

        working_directory = cwd or str(Path(script_path).resolve().parent)
        if debug and suffix == ".py":
            return self._analyze_with_debugger(
                script_path,
                args or [],
                working_directory,
                bounds or CaptureBounds(),
                timeout,
            )

        return self._analyze_plain(
            script_path,
            args or [],
            working_directory,
            suffix,
            interpreter,
            language,
            timeout,
        )

    def _analyze_plain(
        self,
        script_path: str,
        args: list[str],
        cwd: str,
        suffix: str,
        interpreter: list[str],
        language: str,
        timeout: int,
    ) -> AnalyzerResult:
        result = self._execute(script_path, interpreter, args, cwd, timeout)
        return self._result_from_execution(
            result,
            suffix,
            script_path,
            language,
            cwd,
            timeout,
        )

    @staticmethod
    def _script_configuration(suffix: str) -> tuple[list[str], str] | None:
        interpreter = INTERPRETERS.get(suffix)
        language = EXTENSION_LANGUAGE.get(suffix)
        if interpreter is None or language is None:
            return None
        return interpreter, language

    def _unsupported_script_result(self, suffix: str) -> AnalyzerResult:
        supported = ", ".join(sorted(INTERPRETERS))
        return AnalyzerResult(
            analyzer=self.name,
            error=f"Unsupported script type '{suffix}'. Supported extensions: {supported}",
        )

    def _execute(
        self,
        script_path: str,
        interpreter: list[str],
        args: list[str],
        cwd: str,
        timeout: int,
    ) -> ProcessResult:
        # The user explicitly asked to run their own script, so it gets the
        # full environment — unlike scan tools, which run isolated.
        return run(
            [*interpreter, script_path, *args],
            cwd=cwd,
            timeout=timeout,
            env_mode="inherit",
        )

    def _result_from_execution(
        self,
        result: ProcessResult,
        suffix: str,
        script_path: str,
        language: str | None,
        cwd: str,
        timeout: int,
    ) -> AnalyzerResult:
        if result.tool_missing:
            interpreter = INTERPRETERS[suffix][0]
            return AnalyzerResult(
                analyzer=self.name,
                error=f"Interpreter not found: {interpreter}. Install it to run {suffix} scripts.",
            )
        if result.status is ProcessStatus.failed_to_start:
            return AnalyzerResult(analyzer=self.name, error=result.stderr)
        if result.status is ProcessStatus.timed_out:
            return self._timeout_result(script_path, language, cwd, timeout)

        findings = self._findings_from_failure(
            result,
            suffix,
            script_path,
            language,
            cwd,
        )
        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _findings_from_failure(
        self,
        result: ProcessResult,
        suffix: str,
        script_path: str,
        language: str | None,
        cwd: str,
    ) -> list[Finding]:
        if result.returncode == 0:
            return []

        stderr = redact_sensitive_text(result.stderr)
        findings: list[Finding] = []
        if stderr and suffix == ".py":
            findings.extend(self._parse_python_traceback(stderr, script_path, cwd))
        elif stderr and suffix in (".js", ".mjs", ".cjs"):
            findings.extend(self._parse_node_error(stderr, script_path, cwd))
        if findings:
            return findings
        return [
            self._generic_failure(result.returncode, stderr, script_path, language, cwd)
        ]

    def _analyze_with_debugger(
        self,
        script_path: str,
        args: list[str],
        cwd: str,
        bounds: CaptureBounds,
        timeout: int,
    ) -> AnalyzerResult:
        outcome = capture_python_crash_outcome(
            script_path,
            args=args,
            cwd=cwd,
            timeout=timeout,
            bounds=bounds,
        )
        if outcome.status is DebugCaptureStatus.unavailable:
            result = self._execute(script_path, INTERPRETERS[".py"], args, cwd, timeout)
            return self._result_from_execution(
                result, ".py", script_path, "python", cwd, timeout
            )
        if outcome.status is DebugCaptureStatus.timed_out:
            return self._timeout_result(script_path, "python", cwd, timeout)
        if outcome.status is DebugCaptureStatus.failed:
            return AnalyzerResult(
                analyzer=self.name,
                error="Debugger session failed before a complete result was captured.",
            )
        if outcome.capture is not None:
            finding = self._debug_finding(outcome.capture, script_path, cwd)
            return AnalyzerResult(analyzer=self.name, findings=[finding])
        return self._result_from_debug_outcome(outcome, script_path, cwd, timeout)

    def _result_from_debug_outcome(
        self,
        outcome: DebugCaptureOutcome,
        script_path: str,
        cwd: str,
        timeout: int,
    ) -> AnalyzerResult:
        if outcome.returncode is None:
            return AnalyzerResult(
                analyzer=self.name,
                error="Debugger session ended without a process exit code.",
            )
        result = ProcessResult(
            status=ProcessStatus.ok,
            returncode=outcome.returncode,
            stdout=outcome.stdout_tail,
            stderr=outcome.stderr_tail,
        )
        return self._result_from_execution(
            result, ".py", script_path, "python", cwd, timeout
        )

    def _timeout_result(
        self,
        script_path: str,
        language: str | None,
        cwd: str,
        timeout: int,
    ) -> AnalyzerResult:
        finding = Finding(
            category=Category.runtime,
            severity=Severity.error,
            code="RUN-001",
            title="Script timed out",
            description=f"Script was killed after running for {timeout}s without finishing.",
            file_path=self._display_path(script_path, cwd),
            suggestion="Check for infinite loops or blocking calls; profile the slow section.",
            language=language,
            metadata={"timeout_seconds": timeout},
        )
        return AnalyzerResult(analyzer=self.name, findings=[finding])

    def _generic_failure(
        self,
        returncode: int | None,
        stderr: str,
        script_path: str,
        language: str | None,
        cwd: str,
    ) -> Finding:
        tail = "\n".join(stderr.strip().splitlines()[-5:]) or "(no stderr output)"
        return Finding(
            category=Category.runtime,
            severity=Severity.error,
            code="RUN-001",
            title="Script failed",
            description=f"Script exited with code {returncode}. Last stderr lines:\n{tail}",
            file_path=self._display_path(script_path, cwd),
            suggestion="Check the stderr output above for details.",
            language=language,
            metadata={"stderr": stderr[:1000], "returncode": returncode},
        )

    def _debug_finding(
        self,
        capture: DebugCapture,
        script_path: str,
        cwd: str,
    ) -> Finding:
        frames = self._select_debug_frames(capture.frames, cwd)
        anchor = frames[0] if frames else None
        exception_type = capture.exception_type.split(".")[-1]
        suggestion = EXCEPTION_SUGGESTIONS.get(
            exception_type,
            f"Investigate the {exception_type} and fix the root cause.",
        )
        return Finding(
            category=Category.runtime,
            severity=Severity.error,
            code="RUN-004",
            title="Uncaught exception (debugger capture)",
            description=f"{capture.exception_type}: {capture.message}",
            file_path=self._display_path(anchor.file if anchor else script_path, cwd),
            line=anchor.line if anchor else None,
            suggestion=suggestion,
            language="python",
            metadata={"debug": self._debug_metadata(capture, frames, cwd)},
        )

    def _debug_metadata(
        self,
        capture: DebugCapture,
        frames: list[CapturedFrame],
        cwd: str,
    ) -> dict:
        return {
            "exception": {
                "type": capture.exception_type,
                "message": capture.message,
            },
            "frames": [self._frame_metadata(frame, cwd) for frame in frames],
            "stdout_tail": capture.stdout_tail,
            "stderr_tail": capture.stderr_tail,
        }

    def _frame_metadata(self, frame: CapturedFrame, cwd: str) -> dict:
        return {
            "file": self._display_path(frame.file, cwd),
            "line": frame.line,
            "function": frame.function,
            "locals": frame.locals,
            "locals_truncated": frame.locals_truncated,
        }

    def _select_debug_frames(
        self,
        frames: list[CapturedFrame],
        cwd: str,
    ) -> list[CapturedFrame]:
        non_package = [frame for frame in frames if not self._is_package_frame(frame)]
        user_frames = [
            frame for frame in non_package if self._path_is_within(frame.file, cwd)
        ]
        return user_frames or non_package or frames

    @staticmethod
    def _is_package_frame(frame: CapturedFrame) -> bool:
        parts = {part.lower() for part in Path(frame.file).parts}
        return bool({"site-packages", "dist-packages"} & parts)

    @staticmethod
    def _path_is_within(file_path: str, cwd: str) -> bool:
        if not file_path:
            return False
        try:
            return Path(file_path).resolve().is_relative_to(Path(cwd).resolve())
        except OSError:
            return False

    @staticmethod
    def _display_path(file_path: str, cwd: str) -> str:
        if not file_path:
            return file_path
        path = Path(file_path)
        try:
            return path.resolve().relative_to(Path(cwd).resolve()).as_posix()
        except (OSError, ValueError):
            return str(path)

    def _parse_python_traceback(
        self,
        stderr: str,
        script_path: str,
        cwd: str,
    ) -> list[Finding]:
        lines = stderr.strip().splitlines()
        exception_line = self._python_exception_line(lines)
        if not exception_line:
            return []
        file_path, line = self._python_exception_location(lines, script_path)
        exception_type = exception_line.split(":")[0].split(".")[-1].strip()
        suggestion = EXCEPTION_SUGGESTIONS.get(
            exception_type,
            f"Investigate the {exception_type} and fix the root cause.",
        )
        return [
            Finding(
                category=Category.runtime,
                severity=Severity.error,
                code="RUN-002",
                title=f"Runtime error: {exception_type}",
                description=exception_line,
                file_path=self._display_path(file_path, cwd),
                line=line,
                suggestion=suggestion,
                language="python",
                metadata={"traceback": stderr[:2000]},
            )
        ]

    @staticmethod
    def _python_exception_line(lines: list[str]) -> str:
        for line in reversed(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith(("File ", "Traceback")):
                return stripped
        return ""

    @staticmethod
    def _python_exception_location(
        lines: list[str],
        script_path: str,
    ) -> tuple[str, int | None]:
        file_path = script_path
        line_number: int | None = None
        for line in lines:
            match = re.match(r'\s*File "([^"]+)", line (\d+)', line)
            if match:
                file_path = match.group(1)
                line_number = int(match.group(2))
        return file_path, line_number

    def _parse_node_error(
        self,
        stderr: str,
        script_path: str,
        cwd: str,
    ) -> list[Finding]:
        """Parse a Node.js stack trace into a finding."""
        lines = stderr.strip().splitlines()
        exception_line = next(
            (
                ln.strip()
                for ln in lines
                if re.match(r"\w*(?:Error|Exception)\b", ln.strip())
            ),
            "",
        )
        if not exception_line:
            return []
        file_path, line_number = self._node_error_location(lines, script_path)
        suggestion = next(
            (hint for needle, hint in NODE_SUGGESTIONS if needle in stderr),
            "Investigate the error and fix the root cause.",
        )
        exception_type = exception_line.split(":")[0].strip()
        return [
            Finding(
                category=Category.runtime,
                severity=Severity.error,
                code="RUN-003",
                title=f"Runtime error: {exception_type}",
                description=exception_line,
                file_path=self._display_path(file_path, cwd),
                line=line_number,
                suggestion=suggestion,
                language="javascript",
                metadata={"stderr": stderr[:2000]},
            )
        ]

    @staticmethod
    def _node_error_location(
        lines: list[str],
        script_path: str,
    ) -> tuple[str, int | None]:
        for line in lines:
            frame = NODE_FRAME_RE.search(line)
            if frame:
                return frame.group(1), int(frame.group(2))
        return script_path, None
