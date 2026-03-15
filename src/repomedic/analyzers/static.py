"""Static analysis — ruff + ast syntax checks + import graph."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run


@register
class StaticAnalyzer(BaseAnalyzer):
    name = "static"
    description = "Ruff linting, syntax errors, circular dependency detection"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.python_files) > 0

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        # 1. Syntax errors via ast.parse
        findings.extend(self._check_syntax(ctx))

        # 2. Ruff linting
        findings.extend(self._run_ruff(ctx))

        # 3. Bandit security linting
        findings.extend(self._run_bandit(ctx))

        # 4. Circular dependency detection
        findings.extend(self._check_circular_imports(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_syntax(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for py_file in ctx.python_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                ast.parse(source, filename=str(py_file))
            except SyntaxError as e:
                findings.append(
                    Finding(
                        category=Category.static_analysis,
                        severity=Severity.error,
                        code="STATIC-001",
                        title="Syntax error",
                        description=str(e.msg),
                        file_path=str(py_file.relative_to(ctx.target)),
                        line=e.lineno,
                        column=e.offset,
                        suggestion=f"Fix the syntax error: {e.msg}",
                    )
                )
        return findings

    def _run_ruff(self, ctx: ScanContext) -> list[Finding]:
        result = run(
            ["ruff", "check", "--output-format", "json", "--no-fix", str(ctx.target)],
            cwd=str(ctx.target),
            timeout=30,
        )

        if result.returncode < 0:
            return []  # ruff not installed or timed out

        try:
            issues = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError:
            return []

        allowed_files = {str(f.resolve()) for f in ctx.python_files}

        findings = []
        for issue in issues:
            abs_path = str(Path(issue.get("filename", "")).resolve())
            if abs_path not in allowed_files:
                continue

            try:
                rel_path = str(Path(issue["filename"]).relative_to(ctx.target))
            except ValueError:
                rel_path = issue.get("filename", "")

            severity = Severity.warning
            if issue.get("code", "").startswith("E9"):
                severity = Severity.error

            findings.append(
                Finding(
                    category=Category.static_analysis,
                    severity=severity,
                    code=f"STATIC-RUFF-{issue.get('code', '???')}",
                    title=issue.get("code", "unknown"),
                    description=issue.get("message", ""),
                    file_path=rel_path,
                    line=issue.get("location", {}).get("row"),
                    column=issue.get("location", {}).get("column"),
                    suggestion=issue.get("fix", {}).get("message", "")
                    if issue.get("fix")
                    else f"Review and fix {issue.get('code', '')} violation",
                    metadata={"ruff_code": issue.get("code")},
                )
            )
        return findings

    def _run_bandit(self, ctx: ScanContext) -> list[Finding]:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        # bandit -r <dir> -f json -o <file> --quiet
        result = run(
            ["bandit", "-r", str(ctx.target), "-f", "json", "-o", report_path, "-q"],
            cwd=str(ctx.target),
            timeout=60,
        )

        if result.returncode < 0:
            Path(report_path).unlink(missing_ok=True)
            return []  # bandit not installed or timed out

        findings = []
        try:
            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)
            
            allowed_files = {str(f.resolve()) for f in ctx.python_files}
            
            for issue in data.get("results", []):
                abs_path = str(Path(issue.get("filename", "")).resolve())
                if abs_path not in allowed_files:
                    continue
                
                try:
                    rel_path = str(Path(abs_path).relative_to(ctx.target))
                except ValueError:
                    rel_path = issue.get("filename", "")
                
                sev_str = issue.get("issue_severity", "LOW").upper()
                if sev_str == "HIGH":
                    severity = Severity.error
                elif sev_str == "LOW":
                    severity = Severity.info
                else:
                    severity = Severity.warning

                findings.append(
                    Finding(
                        category=Category.security,
                        severity=severity,
                        code=f"BANDIT-{issue.get('test_id', 'UNKNOWN')}",
                        title=issue.get("test_name", "Bandit Warning"),
                        description=issue.get("issue_text", ""),
                        file_path=rel_path,
                        line=issue.get("line_number"),
                        suggestion="Review this security warning from Bandit.",
                        metadata={"confidence": issue.get("issue_confidence")},
                    )
                )

        except (json.JSONDecodeError, FileNotFoundError):
            pass
        finally:
            Path(report_path).unlink(missing_ok=True)

        return findings

    def _check_circular_imports(self, ctx: ScanContext) -> list[Finding]:
        """Build a simple import graph and detect cycles."""
        # Map module name -> set of imported module names (project-local only)
        graph: dict[str, set[str]] = {}
        module_files: dict[str, Path] = {}

        for py_file in ctx.python_files:
            try:
                rel = py_file.relative_to(ctx.target)
            except ValueError:
                continue
            parts = list(rel.with_suffix("").parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                continue
            mod_name = ".".join(parts)
            module_files[mod_name] = py_file

            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except SyntaxError:
                continue

            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.level == 0:
                        imports.add(node.module.split(".")[0])
            graph[mod_name] = imports

        # DFS cycle detection
        project_modules = set(graph.keys())
        findings = []
        visited: set[str] = set()

        def dfs(mod: str, path: list[str]) -> list[str] | None:
            if mod in path:
                return path[path.index(mod) :]
            if mod in visited:
                return None
            visited.add(mod)
            for dep in graph.get(mod, set()):
                if dep in project_modules:
                    cycle = dfs(dep, path + [mod])
                    if cycle is not None:
                        return cycle
            return None

        seen_cycles: set[frozenset[str]] = set()
        for mod in project_modules:
            cycle = dfs(mod, [])
            if cycle:
                key = frozenset(cycle)
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    cycle_str = " -> ".join(cycle + [cycle[0]])
                    findings.append(
                        Finding(
                            category=Category.static_analysis,
                            severity=Severity.warning,
                            code="STATIC-002",
                            title="Circular import detected",
                            description=f"Circular import chain: {cycle_str}",
                            file_path=str(
                                module_files.get(cycle[0], Path()).relative_to(
                                    ctx.target
                                )
                            )
                            if cycle[0] in module_files
                            else None,
                            suggestion="Break the circular import by moving shared code to a separate module or using lazy imports.",
                        )
                    )

        return findings
