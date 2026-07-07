"""The `repomedic agents` command — a self-describing integration guide.

Coding agents can run `repomedic agents` once to learn the whole tool surface
without reading any docs or source. Keep this terse: it lands in an agent's
context window.
"""

from __future__ import annotations

AGENT_GUIDE = """\
# RepoMedic — Agent Integration Guide

RepoMedic is a bug sniffer: it diagnoses a repo and hands you a compact,
structured fix report so you don't burn tokens reading files to find problems.

## The one command you need

    repomedic sniff <path>

Non-interactive. Prints a markdown fix report to stdout (progress goes to
stderr). Exit code 0 = no errors, 1 = errors found. Findings are grouped by
file, each with a stable ID (RM-xxxxxxxx), severity, location, a suggested
fix, and a code snippet of the offending lines.

## Other commands

    repomedic <path> --output json      # full scan, JSON only on stdout
    repomedic sniff <path> --changed    # only findings in git-changed files
    repomedic sniff <path> --since REF  # only findings in files changed since REF
    repomedic run <script>              # execute a script (py/js/sh/rb/php/pl/lua) and analyze the failure
    repomedic doctor <path> --output json    # environment/toolchain health
    repomedic explain <path> --output markdown  # project brief (type, languages, deps)
    repomedic fix <path> --dry-run      # preview safe auto-fixes; drop --dry-run to apply
    repomedic list-analyzers            # available analyzers

## Useful flags (scan and sniff)

    --analyzers static,git,security   # restrict analyzers
    --min-severity warning            # drop info-level findings
    --max-findings 30                 # cap report size (most severe kept; omitted count reported)
    --fail-on error|warning|any|never # what makes the exit code 1
    --report-file PATH                # write the markdown report to a file ('-' = stdout)
    --no-snippets                     # omit code snippets to shrink output

## Exit codes

    0  scan completed, nothing at/above the --fail-on threshold
    1  findings at/above the --fail-on threshold (sniff defaults to --fail-on error)
    2  usage error (bad path, unknown analyzer, ...)

## Token-saving workflow

1. `repomedic sniff . --max-findings 30` — get the prioritized fix list.
2. Fix findings file by file; snippets usually contain enough context.
3. `repomedic sniff . --changed --fail-on error` — re-check only what you touched.
4. Exit code 0 → done.

## Per-repo defaults

Projects can pin scan behavior in `.repomedic.toml` (or `[tool.repomedic]`
in pyproject.toml): analyzers, exclude dirs, min_severity, max_findings,
fail_on, include_tests. CLI flags override the file.
"""


def get_agent_guide() -> str:
    """Return the agent integration guide as markdown."""
    return AGENT_GUIDE
