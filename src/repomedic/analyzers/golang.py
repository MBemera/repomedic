"""Go analyzer — build errors, vet, dependency analysis."""

from __future__ import annotations

import re
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run


@register
class GoAnalyzer(BaseAnalyzer):
    name = "go"
    description = "Build errors, go vet, module verification"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.go_files) > 0 or ctx.has_go_mod

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        # 1. Build check
        findings.extend(self._check_build(ctx))

        # 2. Go vet
        findings.extend(self._run_vet(ctx))

        # 3. Module verification
        findings.extend(self._check_modules(ctx))

        # 4. Vulnerability check
        findings.extend(self._run_govulncheck(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_build(self, ctx: ScanContext) -> list[Finding]:
        """Run go build to detect compile errors."""
        result = run(
            ["go", "build", "./..."],
            cwd=str(ctx.target),
            timeout=60,
        )

        if not result.ran:
            return []  # go not installed

        if result.ok:
            return []

        findings = []
        # Parse go build errors: file.go:line:col: message
        error_text = result.stderr or result.stdout
        for line in error_text.splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.match(r"(.+\.go):(\d+):(\d+):\s+(.+)", line)
            if match:
                filepath, line_no, col, message = match.groups()
                try:
                    rel = str(Path(filepath).relative_to(ctx.target))
                except ValueError:
                    rel = filepath

                findings.append(
                    Finding(
                        category=Category.static_analysis,
                        severity=Severity.error,
                        code="GO-001",
                        title="Go build error",
                        description=message,
                        file_path=rel,
                        line=int(line_no),
                        column=int(col),
                        suggestion=f"Fix the compile error: {message}",
                        language="go",
                    )
                )

        if not findings and not result.ok:
            findings.append(
                Finding(
                    category=Category.static_analysis,
                    severity=Severity.error,
                    code="GO-001",
                    title="Go build failed",
                    description=error_text[:500],
                    suggestion="Fix the build errors reported by 'go build ./...'",
                    language="go",
                    metadata={"stderr": error_text[:2000]},
                )
            )

        return findings

    def _run_vet(self, ctx: ScanContext) -> list[Finding]:
        """Run go vet to detect suspicious constructs."""
        result = run(
            ["go", "vet", "./..."],
            cwd=str(ctx.target),
            timeout=60,
        )

        if not result.ran or result.ok:
            return []

        findings = []
        error_text = result.stderr or result.stdout
        for line in error_text.splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.match(r"(.+\.go):(\d+):(\d+):\s+(.+)", line)
            if match:
                filepath, line_no, col, message = match.groups()
                try:
                    rel = str(Path(filepath).relative_to(ctx.target))
                except ValueError:
                    rel = filepath

                findings.append(
                    Finding(
                        category=Category.static_analysis,
                        severity=Severity.warning,
                        code="GO-002",
                        title="Go vet warning",
                        description=message,
                        file_path=rel,
                        line=int(line_no),
                        column=int(col),
                        suggestion=f"Review and fix: {message}",
                        language="go",
                    )
                )

        return findings

    def _check_modules(self, ctx: ScanContext) -> list[Finding]:
        """Verify Go modules are correct."""
        if not ctx.has_go_mod:
            if ctx.go_files:
                return [
                    Finding(
                        category=Category.dependency,
                        severity=Severity.warning,
                        code="GO-DEP-001",
                        title="No go.mod file",
                        description="Go source files found but no go.mod. This project may not use Go modules.",
                        suggestion="Initialize Go modules: go mod init <module-name>",
                        language="go",
                    )
                ]
            return []

        findings = []

        # Check for missing go.sum
        if not (ctx.target / "go.sum").is_file():
            findings.append(
                Finding(
                    category=Category.dependency,
                    severity=Severity.warning,
                    code="GO-DEP-003",
                    title="No go.sum file",
                    description="go.mod exists but go.sum is missing. Dependencies are not verified.",
                    suggestion="Generate go.sum: go mod tidy",
                    language="go",
                )
            )

        # Verify dependencies
        result = run(
            ["go", "mod", "verify"],
            cwd=str(ctx.target),
            timeout=30,
        )

        if not result.ran:
            return findings

        if not result.ok:
            findings.append(
                Finding(
                    category=Category.dependency,
                    severity=Severity.error,
                    code="GO-DEP-002",
                    title="Go module verification failed",
                    description=(result.stderr or result.stdout).strip()[:500],
                    suggestion="Fix module issues: go mod tidy",
                    language="go",
                )
            )

        return findings

    def _run_govulncheck(self, ctx: ScanContext) -> list[Finding]:
        """Run govulncheck to find Go vulnerabilities."""
        if not ctx.has_go_mod:
            return []

        import json
        result = run(
            ["govulncheck", "-json", "./..."],
            cwd=str(ctx.target),
            timeout=120,
        )

        if not result.ran:
            return []  # govulncheck not installed

        findings = []
        osv_details = {}
        
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "osv" in data and "id" in data["osv"]:
                osv = data["osv"]
                osv_details[osv["id"]] = osv
            elif "finding" in data:
                finding = data["finding"]
                osv_id = finding.get("osv", "UNKNOWN")
                osv_info = osv_details.get(osv_id, {})
                
                trace = finding.get("trace", [])
                if not trace:
                    continue
                # Get the first position in the trace (closest to project code)
                pos = trace[0].get("position", {})
                filepath = pos.get("filename", "")
                line_no = pos.get("line")
                
                try:
                    rel_path = str(Path(filepath).relative_to(ctx.target))
                except ValueError:
                    rel_path = filepath
                
                aliases = ", ".join(osv_info.get("aliases", []))
                
                findings.append(
                    Finding(
                        category=Category.security,
                        severity=Severity.error,
                        code=f"GO-VULN-{osv_id}",
                        title=f"Go Vulnerability: {osv_id} ({aliases})",
                        description=osv_info.get("details", f"Vulnerable code in {trace[0].get('module', '')}")[:500],
                        file_path=rel_path,
                        line=line_no,
                        suggestion=f"Update the vulnerable module {trace[0].get('module', '')}.",
                        language="go",
                    )
                )

        return findings
