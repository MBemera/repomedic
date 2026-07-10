"""Scan orchestration service — the CLI-free pipeline behind scan/sniff.

`run_scan` performs everything the CLI does around `Scanner.scan()` —
target resolution (including cloning GitHub URLs), per-repo config merge,
analyzer-name validation, changed-file scoping — without printing,
prompting, or exiting. That makes the full pipeline reusable by any
frontend: the CLI, an MCP server, an editor extension, or a test harness.

Errors are raised as :class:`ScanServiceError` (carrying the conventional
exit code 2 for usage errors) instead of ``typer.Exit``. Progress messages
go to an optional callback instead of a console.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from repomedic.analyzers import get_all_analyzers
from repomedic.core.config import VALID_FAIL_ON, VALID_SEVERITIES, load_config
from repomedic.core.scanner import Scanner
from repomedic.models import ScanReport
from repomedic.utils.process import run
from repomedic.utils.vcs import changed_files

GITHUB_RE = re.compile(
    r"^(https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?|git@github\.com:[\w\-\.]+/[\w\-\.]+(?:\.git)?)$"
)

ProgressFn = Callable[[str], None]


class ScanServiceError(Exception):
    """A scan could not be started or completed; maps to a CLI exit code."""

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class ScanRequest:
    """Everything needed to run a scan, CLI-independent.

    ``None`` fields mean "use the per-repo config, then the built-in
    default" — mirroring how CLI flags override `.repomedic.toml`.
    """

    target: str
    analyzers: list[str] | None = None
    min_severity: str | None = None
    changed: bool = False
    since: str | None = None
    max_findings: int | None = None
    fail_on: str | None = None
    analyzer_timeout: float | None = None  # None = config default; 0 disables
    allow_exec: bool | None = None  # None = policy default: local yes, remote URL no


@dataclass
class ScanOutcome:
    """A finished scan: the report, its exit code, and clone bookkeeping."""

    report: ScanReport
    exit_code: int
    resolved_target: Path
    was_remote: bool
    fail_on: str = "never"
    _cleaned: bool = field(default=False, repr=False)

    def cleanup(self) -> None:
        """Remove the temporary clone, if any. Idempotent.

        Deferred rather than done inside ``run_scan`` because markdown
        snippet rendering reads the cloned files after the scan.
        """
        if self.was_remote and not self._cleaned:
            shutil.rmtree(self.resolved_target, ignore_errors=True)
            self._cleaned = True


def exit_code_for(report: ScanReport, fail_on: str) -> int:
    """Map summary counts to an exit code according to the fail-on policy."""
    s = report.summary
    if fail_on == "error":
        return 1 if s.errors else 0
    if fail_on == "warning":
        return 1 if s.errors or s.warnings else 0
    if fail_on == "any":
        return 1 if s.total_findings else 0
    return 0  # never


def resolve_target(target: str, progress: ProgressFn | None = None) -> tuple[Path, bool]:
    """Resolve a local path or GitHub URL to a directory. Returns (path, is_temp)."""
    if GITHUB_RE.match(target):
        return _clone_repo(target, progress), True

    path = Path(target).resolve()
    if not path.is_dir():
        raise ScanServiceError(f"{target} is not a directory or valid GitHub URL")
    return path, False


def _clone_repo(url: str, progress: ProgressFn | None = None) -> Path:
    """Clone a GitHub repo into a temp directory and return the path."""
    clone_dir = Path(tempfile.mkdtemp(prefix="repomedic_"))
    if progress:
        progress(f"Cloning {url} ...")
    # `--` guards against argument injection; GIT_TERMINAL_PROMPT=0 keeps the
    # clone from hanging on a credential prompt for private/nonexistent repos.
    result = run(
        ["git", "clone", "--depth", "1", "--", url, str(clone_dir)],
        timeout=120,
        extra_env={"GIT_TERMINAL_PROMPT": "0"},
    )
    if not result.ok:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise ScanServiceError(f"Clone failed: {result.stderr.strip()}")
    if progress:
        progress(f"Cloned to {clone_dir}")
    return clone_dir


def run_scan(req: ScanRequest, *, progress: ProgressFn | None = None) -> ScanOutcome:
    """Run the full scan pipeline. Never prints, prompts, or exits.

    The caller owns ``ScanOutcome.cleanup()`` (idempotent) once this
    returns; on error the temporary clone is already removed.
    """
    if req.min_severity is not None and req.min_severity not in VALID_SEVERITIES:
        raise ScanServiceError(
            f"invalid min_severity '{req.min_severity}' (choose from: {', '.join(sorted(VALID_SEVERITIES))})"
        )
    if req.fail_on is not None and req.fail_on not in VALID_FAIL_ON:
        raise ScanServiceError(
            f"invalid fail_on '{req.fail_on}' (choose from: {', '.join(sorted(VALID_FAIL_ON))})"
        )

    resolved, was_remote = resolve_target(req.target, progress)

    try:
        # Per-repo config supplies defaults; request fields win.
        cfg = load_config(resolved)
        min_severity = req.min_severity or cfg.min_severity
        max_findings = req.max_findings if req.max_findings is not None else cfg.max_findings
        fail_on = req.fail_on or cfg.fail_on or "never"

        analyzer_list = req.analyzers if req.analyzers is not None else cfg.analyzers
        if analyzer_list:
            known = {a.name for a in get_all_analyzers()}
            unknown = [a for a in analyzer_list if a.lower() not in known]
            if unknown:
                raise ScanServiceError(
                    f"unknown analyzer(s): {', '.join(unknown)}. Run `repomedic list-analyzers`."
                )

        only_files: set[str] | None = None
        if req.changed or req.since:
            only_files = changed_files(resolved, since=req.since)
            if only_files is None:
                raise ScanServiceError("--changed/--since requires a git repository")

        if progress:
            label = "all applicable analyzers" if analyzer_list is None else ", ".join(analyzer_list)
            progress(f"Scanning {resolved} with {label} ...")

        analyzer_timeout = (
            req.analyzer_timeout if req.analyzer_timeout is not None else cfg.analyzer_timeout
        )
        scan_kwargs: dict = {}
        if analyzer_timeout is not None:
            scan_kwargs["analyzer_timeout"] = analyzer_timeout

        # Trust policy: local targets run the full toolchain; freshly cloned
        # URLs are untrusted, so code-executing checks are off unless the
        # caller explicitly opts in. Deliberately NOT a .repomedic.toml key —
        # a scanned repo must never be able to grant itself execution.
        allow_exec = req.allow_exec if req.allow_exec is not None else not was_remote

        report = Scanner().scan(
            str(resolved),
            analyzer_names=analyzer_list,
            min_severity=min_severity,
            extra_ignore_dirs=set(cfg.exclude) or None,
            skip_tests=not cfg.include_tests,
            only_files=only_files,
            max_findings=max_findings,
            allow_exec=allow_exec,
            **scan_kwargs,
        )

        if progress and report.languages:
            lang_str = ", ".join(f"{name} ({count})" for name, count in report.languages.items())
            progress(f"Languages: {lang_str}")

        return ScanOutcome(
            report=report,
            exit_code=exit_code_for(report, fail_on),
            resolved_target=resolved,
            was_remote=was_remote,
            fail_on=fail_on,
        )
    except BaseException:
        if was_remote:
            shutil.rmtree(resolved, ignore_errors=True)
        raise
