"""Git health analyzer — merge conflicts, uncommitted changes, .gitignore."""

from __future__ import annotations

import re

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run

MERGE_CONFLICT_RE = re.compile(r"^<{7}\s", re.MULTILINE)


@register
class GitAnalyzer(BaseAnalyzer):
    name = "git"
    description = "Merge conflicts, uncommitted changes, detached HEAD, .gitignore health"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return ctx.has_git

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []
        cwd = str(ctx.target)

        findings.extend(self._check_status(cwd))
        findings.extend(self._check_merge_conflicts(ctx))
        findings.extend(self._check_head(cwd))
        findings.extend(self._check_gitignore(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_status(self, cwd: str) -> list[Finding]:
        result = run(["git", "status", "--porcelain"], cwd=cwd)
        if not result.ok:
            return []

        findings = []
        lines = [ln for ln in result.stdout.strip().splitlines() if ln.strip()]
        if not lines:
            return []

        untracked = [ln for ln in lines if ln.startswith("??")]
        modified = [ln for ln in lines if not ln.startswith("??")]

        if modified:
            findings.append(
                Finding(
                    category=Category.git_health,
                    severity=Severity.warning,
                    code="GIT-001",
                    title="Uncommitted changes",
                    description=f"{len(modified)} file(s) have uncommitted changes.",
                    suggestion="Review and commit or stash your changes.",
                    metadata={"files": [ln[3:] for ln in modified]},
                )
            )

        if untracked:
            findings.append(
                Finding(
                    category=Category.git_health,
                    severity=Severity.info,
                    code="GIT-002",
                    title="Untracked files",
                    description=f"{len(untracked)} untracked file(s).",
                    suggestion="Add files to .gitignore or track them with git add.",
                    metadata={"files": [ln[3:] for ln in untracked]},
                )
            )

        return findings

    def _check_merge_conflicts(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for fpath in ctx.files:
            if fpath.suffix in (".pyc", ".pyo", ".so", ".dll", ".exe", ".bin"):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if MERGE_CONFLICT_RE.search(content):
                try:
                    rel = str(fpath.relative_to(ctx.target))
                except ValueError:
                    rel = str(fpath)
                findings.append(
                    Finding(
                        category=Category.git_health,
                        severity=Severity.error,
                        code="GIT-003",
                        title="Merge conflict markers found",
                        description="File contains unresolved merge conflict markers.",
                        file_path=rel,
                        suggestion="Resolve the merge conflicts by choosing the correct code and removing the conflict markers (<<<<<<<, =======, >>>>>>>).",
                    )
                )
        return findings

    def _check_head(self, cwd: str) -> list[Finding]:
        result = run(["git", "symbolic-ref", "HEAD"], cwd=cwd)
        if result.ran and result.returncode != 0:
            return [
                Finding(
                    category=Category.git_health,
                    severity=Severity.warning,
                    code="GIT-004",
                    title="Detached HEAD",
                    description="Repository is in detached HEAD state.",
                    suggestion="Checkout a branch with: git checkout <branch-name>",
                )
            ]
        return []

    def _check_gitignore(self, ctx: ScanContext) -> list[Finding]:
        gitignore = ctx.target / ".gitignore"
        if not gitignore.is_file():
            return [
                Finding(
                    category=Category.git_health,
                    severity=Severity.info,
                    code="GIT-005",
                    title="No .gitignore file",
                    description="Project has no .gitignore file.",
                    suggestion="Create a .gitignore file to exclude build artifacts, caches, and IDE files.",
                )
            ]
        return []
