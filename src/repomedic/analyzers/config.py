"""Config file validator — project configs, universal data-file syntax, project docs."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity

# Skip syntax checks on data files bigger than this (lock files, datasets).
MAX_DATA_FILE_BYTES = 1024 * 1024


@register
class ConfigAnalyzer(BaseAnalyzer):
    name = "config"
    description = "Config validation, JSON/YAML/TOML syntax, README/LICENSE presence"

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

        findings.extend(self._check_data_file_syntax(ctx))
        findings.extend(self._check_project_docs(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_data_file_syntax(self, ctx: ScanContext) -> list[Finding]:
        """Syntax-check every JSON/TOML/YAML file — language-agnostic, zero-config."""
        findings = []
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            yaml = None

        for f in ctx.data_files:
            try:
                if f.stat().st_size > MAX_DATA_FILE_BYTES:
                    continue
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            suffix = f.suffix.lower()
            error: str | None = None
            line: int | None = None

            if suffix == ".json":
                # package.json/pyproject.toml already get richer checks above
                if f.name == "package.json":
                    continue
                try:
                    json.loads(content)
                except json.JSONDecodeError as e:
                    error, line = e.msg, e.lineno
            elif suffix == ".toml":
                if f.name == "pyproject.toml":
                    continue
                try:
                    tomllib.loads(content)
                except tomllib.TOMLDecodeError as e:
                    error = str(e)
            elif suffix in (".yaml", ".yml") and yaml is not None:
                try:
                    list(yaml.safe_load_all(content))
                except yaml.YAMLError as e:
                    error = str(e).split("\n")[0]
                    mark = getattr(e, "problem_mark", None)
                    if mark is not None:
                        line = mark.line + 1

            if error:
                fmt = suffix.lstrip(".").upper()
                findings.append(
                    Finding(
                        category=Category.config,
                        severity=Severity.error,
                        code="CFG-010",
                        title=f"Invalid {fmt} syntax",
                        description=f"Failed to parse {f.name}: {error}",
                        file_path=self._rel(f, ctx),
                        line=line,
                        suggestion=f"Fix the {fmt} syntax error so the file parses.",
                    )
                )
        return findings

    def _check_project_docs(self, ctx: ScanContext) -> list[Finding]:
        """Flag missing README and LICENSE at the project root."""
        findings = []
        has_readme = any(
            (ctx.target / name).is_file()
            for name in ("README.md", "README.rst", "README.txt", "README", "readme.md")
        )
        if not has_readme:
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.info,
                    code="CFG-011",
                    title="No README file",
                    description="The project has no README at its root.",
                    suggestion="Add a README.md describing what the project does and how to run it.",
                )
            )

        has_license = any(
            (ctx.target / name).is_file()
            for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")
        )
        if not has_license:
            findings.append(
                Finding(
                    category=Category.config,
                    severity=Severity.info,
                    code="CFG-012",
                    title="No LICENSE file",
                    description="The project has no LICENSE file at its root.",
                    suggestion="Add a LICENSE file if this code will be shared or published.",
                )
            )
        return findings

    def _check_pyproject(self, path: Path, ctx: ScanContext) -> list[Finding]:
        findings = []
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
