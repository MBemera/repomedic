"""Dependency analyzer — missing/conflicting packages, venv health."""

from __future__ import annotations

import json
import logging
import re

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run

logger = logging.getLogger("repomedic")


def parse_dep_name(spec: str) -> str:
    """Extract the package name from a dependency specifier like 'requests>=2.0'."""
    return re.split(r"[>=<!\[;]", spec)[0].strip()


@register
class DependencyAnalyzer(BaseAnalyzer):
    name = "dependencies"
    description = "Missing/conflicting packages, venv health"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return ctx.has_pyproject or ctx.has_requirements_txt or len(ctx.python_files) > 0

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        findings.extend(self._check_venv(ctx))
        findings.extend(self._check_installed_vs_required(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_venv(self, ctx: ScanContext) -> list[Finding]:
        """Check whether the target project has a virtualenv."""
        venv_dirs = [ctx.target / d for d in (".venv", "venv", "env")]
        has_venv_dir = any(d.is_dir() for d in venv_dirs)

        if not has_venv_dir and ctx.has_pyproject:
            return [
                Finding(
                    category=Category.dependency,
                    severity=Severity.info,
                    code="DEP-001",
                    title="No virtual environment detected",
                    description="No .venv/venv directory found in the target project.",
                    suggestion="Create a virtual environment: python -m venv .venv && source .venv/bin/activate",
                )
            ]
        return []

    def _find_target_python(self, ctx: ScanContext) -> str | None:
        """Find the Python executable for the target project's venv."""
        for d in (".venv", "venv", "env"):
            venv_python = ctx.target / d / "bin" / "python"
            if venv_python.is_file():
                return str(venv_python)
            # Windows fallback
            venv_python_win = ctx.target / d / "Scripts" / "python.exe"
            if venv_python_win.is_file():
                return str(venv_python_win)
        return None

    def _check_installed_vs_required(self, ctx: ScanContext) -> list[Finding]:
        """Compare declared requirements with installed packages."""
        required = self._parse_requirements(ctx)
        if not required:
            return []

        # Use the target project's venv python if available
        target_python = self._find_target_python(ctx)
        if target_python is None:
            return []  # can't check without a venv

        result = run([target_python, "-m", "pip", "list", "--format", "json"], timeout=15)
        if result.returncode != 0:
            return []

        try:
            installed_list = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        installed = {pkg["name"].lower().replace("-", "_"): pkg["version"] for pkg in installed_list}

        findings = []
        for req_name in required:
            normalized = req_name.lower().replace("-", "_")
            if normalized not in installed:
                findings.append(
                    Finding(
                        category=Category.dependency,
                        severity=Severity.error,
                        code="DEP-002",
                        title=f"Missing package: {req_name}",
                        description=f"Package '{req_name}' is declared as a dependency but not installed.",
                        suggestion=f"Install the package: pip install {req_name}",
                    )
                )
        return findings

    def _parse_requirements(self, ctx: ScanContext) -> list[str]:
        """Extract package names from requirements.txt or pyproject.toml."""
        names: list[str] = []

        req_file = ctx.target / "requirements.txt"
        if req_file.is_file():
            for line in req_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    name = parse_dep_name(line)
                    if name:
                        names.append(name)

        pyproject = ctx.target / "pyproject.toml"
        if pyproject.is_file():
            import tomllib
            try:
                data = tomllib.loads(pyproject.read_text())
                deps = data.get("project", {}).get("dependencies", [])
                for dep in deps:
                    name = parse_dep_name(dep)
                    if name:
                        names.append(name)
            except Exception as exc:
                logger.warning("Failed to parse pyproject.toml dependencies: %s", exc)

        return names
