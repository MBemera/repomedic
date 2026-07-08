"""Shell analyzer — bash syntax checks and ShellCheck linting."""

from __future__ import annotations

import json
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run


@register
class ShellAnalyzer(BaseAnalyzer):
    name = "shell"
    description = "Shell script syntax checks (bash -n) and ShellCheck linting"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.shell_files) > 0

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []
        findings.extend(self._check_syntax(ctx))
        findings.extend(self._run_shellcheck(ctx))
        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_syntax(self, ctx: ScanContext) -> list[Finding]:
        """Run `bash -n` on each script to catch syntax errors."""
        findings = []
        for script in ctx.shell_files:
            if script.suffix == ".zsh":
                continue  # bash -n would false-positive on zsh-specific syntax
            result = run(["bash", "-n", str(script)], cwd=str(ctx.target), timeout=10)
            if result.returncode <= 0:
                continue  # clean, or bash unavailable
            message = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "Syntax error"
            line_no = None
            # bash errors look like: file.sh: line 12: syntax error near ...
            for part in message.split(":"):
                part = part.strip()
                if part.startswith("line "):
                    try:
                        line_no = int(part.removeprefix("line ").strip())
                    except ValueError:
                        pass
                    break
            findings.append(
                Finding(
                    category=Category.static_analysis,
                    severity=Severity.error,
                    code="SH-001",
                    title="Shell syntax error",
                    description=message,
                    file_path=self._rel(script, ctx),
                    line=line_no,
                    suggestion="Fix the shell syntax error reported by `bash -n`.",
                    language="shell",
                )
            )
        return findings

    def _run_shellcheck(self, ctx: ScanContext) -> list[Finding]:
        """Run ShellCheck (if installed) across all shell scripts."""
        scripts = [str(s) for s in ctx.shell_files if s.suffix != ".zsh"]
        if not scripts:
            return []

        result = run(
            ["shellcheck", "--format", "json", *scripts],
            cwd=str(ctx.target),
            timeout=60,
        )
        if result.returncode < 0:
            return []  # shellcheck not installed

        try:
            issues = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError:
            return []

        severity_map = {
            "error": Severity.error,
            "warning": Severity.warning,
            "info": Severity.info,
            "style": Severity.info,
        }

        findings = []
        for issue in issues:
            sc_code = issue.get("code", 0)
            findings.append(
                Finding(
                    category=Category.static_analysis,
                    severity=severity_map.get(issue.get("level", "warning"), Severity.warning),
                    code=f"SH-SC{sc_code}",
                    title=f"ShellCheck SC{sc_code}",
                    description=issue.get("message", ""),
                    file_path=self._rel(Path(issue.get("file", "")), ctx),
                    line=issue.get("line"),
                    column=issue.get("column"),
                    suggestion=f"See https://www.shellcheck.net/wiki/SC{sc_code} for the fix.",
                    language="shell",
                    metadata={"shellcheck_code": sc_code},
                )
            )
        return findings
