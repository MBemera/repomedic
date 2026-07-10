"""Static analysis — ruff + ast syntax checks + import graph."""

from __future__ import annotations

import ast
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer, map_severity
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import JSON_REPORT_PLACEHOLDER, run_json_tool


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
                        file_path=self._rel(py_file, ctx),
                        line=e.lineno,
                        column=e.offset,
                        suggestion=f"Fix the syntax error: {e.msg}",
                    )
                )
        return findings

    def _run_ruff(self, ctx: ScanContext) -> list[Finding]:
        issues, _result = run_json_tool(
            ["ruff", "check", "--output-format", "json", "--no-fix", str(ctx.target)],
            cwd=str(ctx.target),
            timeout=30,
        )
        if not isinstance(issues, list):
            return []  # ruff not installed, timed out, or no JSON

        allowed_files = {str(f.resolve()) for f in ctx.python_files}

        findings = []
        for issue in issues:
            abs_path = str(Path(issue.get("filename", "")).resolve())
            if abs_path not in allowed_files:
                continue

            rel_path = self._rel(Path(issue.get("filename", "")), ctx)

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
        data, _result = run_json_tool(
            ["bandit", "-r", str(ctx.target), "-f", "json", "-o", JSON_REPORT_PLACEHOLDER, "-q"],
            cwd=str(ctx.target),
            timeout=60,
        )
        if not isinstance(data, dict):
            return []  # bandit not installed, timed out, or no JSON

        allowed_files = {str(f.resolve()) for f in ctx.python_files}

        findings = []
        for issue in data.get("results", []):
            abs_path = str(Path(issue.get("filename", "")).resolve())
            if abs_path not in allowed_files:
                continue

            metadata: dict = {"confidence": issue.get("issue_confidence")}
            # B105/B106/B107 flag hardcoded passwords — the flagged line
            # contains the secret, so the snippet renderer must withhold it.
            if issue.get("test_id") in ("B105", "B106", "B107"):
                metadata["contains_secret"] = True

            findings.append(
                Finding(
                    category=Category.security,
                    severity=map_severity("bandit", issue.get("issue_severity", "LOW"), Severity.warning),
                    code=f"BANDIT-{issue.get('test_id', 'UNKNOWN')}",
                    title=issue.get("test_name", "Bandit Warning"),
                    description=issue.get("issue_text", ""),
                    file_path=self._rel(Path(abs_path), ctx),
                    line=issue.get("line_number"),
                    suggestion="Review this security warning from Bandit.",
                    metadata=metadata,
                )
            )

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
                            file_path=self._rel(module_files[cycle[0]], ctx)
                            if cycle[0] in module_files
                            else None,
                            suggestion="Break the circular import by moving shared code to a separate module or using lazy imports.",
                        )
                    )

        return findings
