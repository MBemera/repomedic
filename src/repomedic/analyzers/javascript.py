"""JavaScript/TypeScript analyzer — syntax checks, ESLint, dependency analysis."""

from __future__ import annotations

import json
import re
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer, map_severity
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run, run_json_tool


@register
class JavaScriptAnalyzer(BaseAnalyzer):
    name = "javascript"
    description = "Syntax errors, ESLint linting, TypeScript checks, dependency analysis"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.js_ts_files) > 0 or ctx.has_package_json

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []
        skipped: list[str] = []

        # 1. Syntax checks (node --check parses only, never executes)
        findings.extend(self._check_syntax(ctx))

        # ESLint loads the repo's own eslint.config.js, and npx resolves
        # repo-controlled node_modules/.bin — code execution by scan.
        if ctx.allow_exec:
            # 2. ESLint linting
            findings.extend(self._run_eslint(ctx))

            # 3. TypeScript type checking
            findings.extend(self._run_tsc(ctx))

            # 4. npm audit for vulnerabilities
            findings.extend(self._run_npm_audit(ctx))
        else:
            skipped += ["eslint", "tsc", "npm-audit"]

        # 5. Dependency presence analysis (pure file checks)
        findings.extend(self._check_dependencies(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings, skipped_checks=skipped)

    def _check_syntax(self, ctx: ScanContext) -> list[Finding]:
        """Run node --check on JavaScript files to detect syntax errors."""
        findings = []
        js_files = [f for f in ctx.js_ts_files if f.suffix in {".js", ".mjs", ".cjs"}]

        for js_file in js_files:
            result = run(
                ["node", "--check", str(js_file)],
                cwd=str(ctx.target),
                timeout=10,
            )
            if result.ran and not result.ok and result.stderr:
                # Parse the error message
                error_msg = result.stderr.strip()
                line_num = None
                # Try to extract line number from error like "file.js:10"
                for err_line in error_msg.splitlines():
                    if ":" in err_line:
                        parts = err_line.split(":")
                        for part in parts:
                            try:
                                line_num = int(part.strip())
                                break
                            except ValueError:
                                continue
                    if line_num:
                        break

                rel = self._rel(js_file, ctx)

                findings.append(
                    Finding(
                        category=Category.static_analysis,
                        severity=Severity.error,
                        code="JS-001",
                        title="JavaScript syntax error",
                        description=error_msg.splitlines()[-1] if error_msg else "Syntax error detected",
                        file_path=rel,
                        line=line_num,
                        suggestion="Fix the syntax error in the JavaScript file.",
                        language="javascript",
                    )
                )
        return findings

    def _run_eslint(self, ctx: ScanContext) -> list[Finding]:
        """Run ESLint if available."""
        data, _result = run_json_tool(
            ["npx", "--no-install", "eslint", "--format", "json", str(ctx.target)],
            cwd=str(ctx.target),
            timeout=60,
        )
        if not isinstance(data, list):
            return []  # eslint not available or no JSON

        findings = []
        for file_result in data:
            rel = self._rel(Path(file_result.get("filePath", "")), ctx)

            for msg in file_result.get("messages", []):
                severity = map_severity("eslint", msg.get("severity", 1))
                findings.append(
                    Finding(
                        category=Category.static_analysis,
                        severity=severity,
                        code=f"JS-ESLINT-{msg.get('ruleId', 'unknown')}",
                        title=msg.get("ruleId", "ESLint issue"),
                        description=msg.get("message", ""),
                        file_path=rel,
                        line=msg.get("line"),
                        column=msg.get("column"),
                        suggestion=f"Fix the ESLint violation: {msg.get('ruleId', '')}",
                        language="javascript",
                        metadata={"eslint_rule": msg.get("ruleId")},
                    )
                )
        return findings

    def _run_tsc(self, ctx: ScanContext) -> list[Finding]:
        """Run TypeScript compiler in check mode if tsconfig.json exists."""
        if not ctx.has_tsconfig:
            return []

        result = run(
            ["npx", "--no-install", "tsc", "--noEmit", "--pretty", "false"],
            cwd=str(ctx.target),
            timeout=60,
        )

        if not result.ran or result.ok:
            return []  # not available or no errors

        findings = []
        # Parse tsc output: file(line,col): error TS1234: message
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # Match pattern: file.ts(10,5): error TS2345: message
            match = re.match(r"(.+?)\((\d+),(\d+)\):\s+(error|warning)\s+(TS\d+):\s+(.+)", line)
            if match:
                filepath, line_no, col, level, code, message = match.groups()
                rel = self._rel(Path(filepath), ctx)

                findings.append(
                    Finding(
                        category=Category.static_analysis,
                        severity=Severity.error if level == "error" else Severity.warning,
                        code=f"JS-TSC-{code}",
                        title=f"TypeScript error: {code}",
                        description=message,
                        file_path=rel,
                        line=int(line_no),
                        column=int(col),
                        suggestion=f"Fix the TypeScript error: {message}",
                        language="javascript",
                        metadata={"tsc_code": code},
                    )
                )
        return findings

    def _check_dependencies(self, ctx: ScanContext) -> list[Finding]:
        """Check if package.json dependencies are installed."""
        findings: list[Finding] = []
        pkg_json = ctx.target / "package.json"
        if not pkg_json.is_file():
            return findings

        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return findings

        # Check if node_modules exists
        node_modules = ctx.target / "node_modules"
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        if all_deps and not node_modules.is_dir():
            findings.append(
                Finding(
                    category=Category.dependency,
                    severity=Severity.error,
                    code="JS-DEP-001",
                    title="node_modules not found",
                    description=f"package.json declares {len(all_deps)} dependencies but node_modules is missing.",
                    suggestion="Install dependencies: npm install",
                    language="javascript",
                )
            )

        # Check for missing lock file
        has_lock = (
            (ctx.target / "package-lock.json").is_file()
            or (ctx.target / "yarn.lock").is_file()
            or (ctx.target / "pnpm-lock.yaml").is_file()
        )
        if all_deps and not has_lock:
            findings.append(
                Finding(
                    category=Category.dependency,
                    severity=Severity.warning,
                    code="JS-DEP-002",
                    title="No package lock file",
                    description="No package-lock.json, yarn.lock, or pnpm-lock.yaml found.",
                    suggestion="Generate a lock file: npm install (creates package-lock.json)",
                    language="javascript",
                )
            )

        return findings

    def _run_npm_audit(self, ctx: ScanContext) -> list[Finding]:
        """Run npm audit to find vulnerable dependencies."""
        if not (ctx.target / "package.json").is_file():
            return []

        data, _result = run_json_tool(
            ["npm", "audit", "--json"],
            cwd=str(ctx.target),
            timeout=60,
        )
        if not isinstance(data, dict):
            return []  # npm not installed or no JSON

        findings = []
        vulns = data.get("vulnerabilities", {})
        for pkg_name, details in vulns.items():
            sev_str = details.get("severity", "moderate").lower()
            severity = map_severity("npm_audit", sev_str, Severity.info)

            findings.append(
                Finding(
                    category=Category.security,
                    severity=severity,
                    code=f"NPM-AUDIT-{pkg_name}",
                    title=f"Vulnerable dependency: {pkg_name}",
                    description=f"Package '{pkg_name}' has a {sev_str} severity vulnerability.",
                    file_path="package.json",
                    suggestion=f"Run `npm audit fix` or update {pkg_name}. Review npm audit logs for details.",
                    language="javascript",
                    metadata={"npm_audit_severity": sev_str},
                )
            )

        return findings
