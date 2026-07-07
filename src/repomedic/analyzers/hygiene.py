"""Hygiene analyzer — repo-wide housekeeping: huge files, stale TODOs, broken symlinks."""

from __future__ import annotations

import re

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.core.languages import language_for_path
from repomedic.models import AnalyzerResult, Category, Finding, Severity

LARGE_FILE_WARN_BYTES = 10 * 1024 * 1024  # 10 MB
LARGE_FILE_ERROR_BYTES = 50 * 1024 * 1024  # 50 MB

TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
TODO_REPORT_THRESHOLD = 10  # only report when markers accumulate


@register
class HygieneAnalyzer(BaseAnalyzer):
    name = "hygiene"
    description = "Oversized files, TODO/FIXME buildup, broken symlinks"

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []
        findings.extend(self._check_large_files(ctx))
        findings.extend(self._check_todo_density(ctx))
        findings.extend(self._check_broken_symlinks(ctx))
        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_large_files(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for f in ctx.files:
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if size < LARGE_FILE_WARN_BYTES:
                continue
            size_mb = size / (1024 * 1024)
            severity = Severity.error if size >= LARGE_FILE_ERROR_BYTES else Severity.warning
            findings.append(
                Finding(
                    category=Category.hygiene,
                    severity=severity,
                    code="HYG-001",
                    title=f"Large file: {size_mb:.0f} MB",
                    description=f"File is {size_mb:.1f} MB. Large files bloat the repo and slow down clones and tooling.",
                    file_path=self._rel(f, ctx),
                    suggestion="Move large assets to object storage or Git LFS, or add the file to .gitignore if it is a build artifact.",
                    metadata={"size_bytes": size},
                )
            )
        return findings

    def _check_todo_density(self, ctx: ScanContext) -> list[Finding]:
        """One aggregate finding when TODO/FIXME markers pile up."""
        per_file: dict[str, int] = {}
        total = 0
        for f in ctx.files:
            if not language_for_path(f):
                continue  # only source files
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            count = len(TODO_RE.findall(content))
            if count:
                per_file[self._rel(f, ctx)] = count
                total += count

        if total < TODO_REPORT_THRESHOLD:
            return []

        top = sorted(per_file.items(), key=lambda kv: -kv[1])[:5]
        top_str = ", ".join(f"{path} ({count})" for path, count in top)
        return [
            Finding(
                category=Category.hygiene,
                severity=Severity.info,
                code="HYG-002",
                title=f"{total} TODO/FIXME markers across {len(per_file)} files",
                description=f"Highest concentrations: {top_str}",
                suggestion="Triage the TODO/FIXME markers: convert real work into tracked issues and delete stale ones.",
                metadata={"total": total, "top_files": dict(top)},
            )
        ]

    def _check_broken_symlinks(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for entry in ctx.target.rglob("*"):
            if not entry.is_symlink():
                continue
            rel_parts = entry.relative_to(ctx.target).parts
            if any(part in {".git", "node_modules", ".venv", "venv"} for part in rel_parts):
                continue
            if not entry.exists():  # target missing
                findings.append(
                    Finding(
                        category=Category.hygiene,
                        severity=Severity.warning,
                        code="HYG-003",
                        title="Broken symlink",
                        description=f"Symlink points to a missing target: {entry.readlink()}",
                        file_path=self._rel(entry, ctx),
                        suggestion="Fix the symlink target or delete the dangling link.",
                    )
                )
        return findings
