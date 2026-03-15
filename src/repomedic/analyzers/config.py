"""Config file validator — pyproject.toml, package.json, Dockerfile, .env."""

from __future__ import annotations

import json
import re
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity


@register
class ConfigAnalyzer(BaseAnalyzer):
    name = "config"
    description = "Validate pyproject.toml, package.json, Dockerfile, .env files"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.config_files) > 0

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        for cfg in ctx.config_files:
            if cfg.name == "pyproject.toml":
                findings.extend(self._check_pyproject(cfg, ctx))
            elif cfg.name == "package.json":
                findings.extend(self._check_package_json(cfg, ctx))
            elif cfg.name == "Dockerfile":
                findings.extend(self._check_dockerfile(cfg, ctx))
            elif cfg.name == ".env":
                findings.extend(self._check_env(cfg, ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_pyproject(self, path: Path, ctx: ScanContext) -> list[Finding]:
        findings = []
        import tomllib

        try:
            data = tomllib.loads(path.read_text())
        except Exception as e:
            return [
                Finding(
                    category=Category.config,
                    severity=Severity.error,
                    code="CFG-001",
                    title="Invalid pyproject.toml",
                    description=f"Failed to parse pyproject.toml: {e}",
                    file_path=self._rel(path, ctx),
                    suggestion="Fix the TOML syntax error in pyproject.toml.",
                )
            ]

        project = data.get("project", {})
        if not project.get("name"):
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.warning,
                    code="CFG-002",
                    title="Missing project name",
                    description="pyproject.toml has no [project] name field.",
                    file_path=self._rel(path, ctx),
                    suggestion="Add a 'name' field under [project] in pyproject.toml.",
                )
            )

        if not data.get("build-system"):
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.warning,
                    code="CFG-003",
                    title="Missing build-system",
                    description="pyproject.toml has no [build-system] section.",
                    file_path=self._rel(path, ctx),
                    suggestion="Add a [build-system] section with requires and build-backend.",
                )
            )

        return findings

    def _check_package_json(self, path: Path, ctx: ScanContext) -> list[Finding]:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            return [
                Finding(
                    category=Category.config,
                    severity=Severity.error,
                    code="CFG-004",
                    title="Invalid package.json",
                    description=f"Failed to parse package.json: {e}",
                    file_path=self._rel(path, ctx),
                    suggestion="Fix the JSON syntax error in package.json.",
                )
            ]

        findings = []
        if not data.get("name"):
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.warning,
                    code="CFG-005",
                    title="Missing name in package.json",
                    description="package.json has no 'name' field.",
                    file_path=self._rel(path, ctx),
                    suggestion="Add a 'name' field to package.json.",
                )
            )
        return findings

    def _check_dockerfile(self, path: Path, ctx: ScanContext) -> list[Finding]:
        findings = []
        content = path.read_text()

        if not re.search(r"^\s*FROM\s", content, re.MULTILINE | re.IGNORECASE):
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.error,
                    code="CFG-006",
                    title="Dockerfile missing FROM",
                    description="Dockerfile does not contain a FROM instruction.",
                    file_path=self._rel(path, ctx),
                    suggestion="Add a FROM instruction to specify the base image.",
                )
            )

        if ":latest" in content:
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.warning,
                    code="CFG-007",
                    title="Dockerfile uses :latest tag",
                    description="Using :latest tag can lead to non-reproducible builds.",
                    file_path=self._rel(path, ctx),
                    suggestion="Pin the image to a specific version tag for reproducible builds.",
                )
            )

        return findings

    def _check_env(self, path: Path, ctx: ScanContext) -> list[Finding]:
        findings = []
        for i, line in enumerate(path.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                findings.append(
                    Finding(
                        category=Category.config,
                        severity=Severity.warning,
                        code="CFG-008",
                        title="Invalid .env line",
                        description=f"Line {i} does not contain '=' separator.",
                        file_path=self._rel(path, ctx),
                        line=i,
                        suggestion="Each line in .env should be KEY=VALUE format.",
                    )
                )
        return findings
