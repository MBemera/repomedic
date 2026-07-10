# Changelog

## Unreleased

### Added
- Headless, stdlib-only DAP client with bounded messages, request correlation,
  event queues, wall-clock deadlines, and fail-closed protocol validation.
- Python crash capture through loopback-only `debugpy`, including bounded
  frames, depth-one locals, output tails, secret redaction, and process-group
  cleanup on timeout.
- `repomedic debug SCRIPT [ARGS…]` and `repomedic run --debug`, with JSON,
  rich, and markdown output plus `--timeout`, `--max-frames`, and `--max-vars`.
- `RUN-004` debugger findings anchored at the deepest user frame. JSON carries
  structured debug metadata; markdown quarantines it in a dynamic fenced block.

### Fixed
- Runtime debug fallback no longer risks executing a clean, failed, or timed-out
  script twice when debugger capture returns no exception.
- Runtime stderr is redacted before traceback findings or metadata are created.
- CLI tests explicitly separate stderr from stdout across supported Typer/Click
  versions, preserving the machine-output contract in the test harness.

## 0.3.0 (2026-07-10)

Hardening release: RepoMedic is now safe to point at untrusted repos, and
its reports are safe to feed to agents. Report schema bumps to **3**.

**Schema policy** (applies from here on): `schema_version` bumps only on
removed/renamed fields or semantics changes; additive fields never bump.
Non-scan command payloads (doctor/explain/fix/list-analyzers) carry their
own independent `schema_version` (currently 1).

### Security
- **Trust model**: new `--exec/--no-exec` gates checks that execute
  repo-controlled code (`cargo check`/`clippy`, `go build`/`vet`/
  `govulncheck`, `npx eslint`/`tsc`, `npm audit`). Local paths default
  `--exec`; GitHub-URL targets default `--no-exec`. Skipped checks are
  reported per analyzer (`skipped_checks`), in the markdown "Analyzer
  notes" section, and as `exec: allowed|disabled` in the front matter.
  Deliberately not configurable from the scanned repo's own config.
- **Secret redaction**: detected secret values are masked everywhere
  (prefix + hash handle + length). Raw gitleaks matches are no longer
  stored in finding metadata, and snippets are withheld for
  secret-bearing findings — `--output json` and the fix report no longer
  print secrets verbatim.
- **Report sanitization**: finding titles/descriptions/suggestions are
  neutralized before rendering (headings can't be forged, fences can't be
  closed from inside, the YAML front matter can't be broken). The agent
  instructions now state that fenced content is untrusted repo data. The
  rich TUI escapes repo-controlled text so it can't inject styling.
- **Scan containment**: file discovery never follows directory symlinks
  and drops file symlinks that resolve outside the scan root; snippet
  rendering enforces the same rule. Git inspection forces
  `core.fsmonitor=false` and an empty `hooksPath` so a repo's own
  `.git/config` can't execute commands during `git status`.
- **Subprocess isolation**: child processes get an allowlisted
  environment by default (`AWS_*`, `GITHUB_TOKEN`, etc. never reach
  repo tools); output capture is capped at 1 MiB/stream; timeouts kill
  the whole process group. `repomedic run` keeps the full environment
  (the user asked to run their own script). Clones pass `--` and
  `GIT_TERMINAL_PROMPT=0`.

### Changed
- **Fingerprints (v2)**: `RM-…` IDs now hash the flagged line's content
  plus an occurrence index instead of the line number — inserting or
  deleting lines above a finding no longer changes its ID. Editing the
  flagged line does (it's a different finding).
- **Process results**: tool invocations report a distinct status
  (`ok`/`not_found`/`timed_out`/`failed_to_start`) instead of sentinel
  return codes that collided with signal deaths. A linter killed by a
  signal is no longer misread as "not installed" (which also fixes a
  fake "JavaScript syntax error" when node was missing and a fake
  "Detached HEAD" when git was missing).
- **Per-analyzer timeout**: `--analyzer-timeout` (default 120s; config
  key `analyzer_timeout`) abandons a hung analyzer instead of hanging
  the scan.
- **Typed command payloads**: `doctor`, `explain`, `fix`, and
  `list-analyzers` JSON output are now versioned pydantic models
  (`schema_version: 1`) instead of ad-hoc dicts. `fix -o json` returns
  `{target, dry_run, actions: […]}`; `list-analyzers -o json` returns
  `{analyzers: […]}`.
- Scan orchestration extracted into an embeddable service
  (`repomedic.core.service.run_scan`) that never prints, prompts, or
  exits — reusable by MCP servers, editors, and test harnesses.
- `--changed`/`--since` parse `git status -z` (quoted/unicode paths
  survive); front-matter string values are JSON-quoted.
- Package ships `py.typed`; CI (ruff, mypy, pytest on 3.11–3.13) runs on
  every push.

## 0.2.0 (2026-07-07)

Agent-first refactor: repomedic is now designed to be operated by AI coding
agents as a bug sniffer, while keeping the human-friendly terminal UI.

### Added
- `repomedic sniff` — the agent command: non-interactive scan, markdown fix
  report on stdout, exit 1 on errors, output capped to the 50 most severe
  findings by default
- Redesigned agent handoff report: YAML front matter (machine-readable
  counts), findings grouped by file, stable `RM-xxxxxxxx` fingerprints,
  code snippets of offending lines, analyzer-failure section, and
  per-language "Verify after fixing" commands
- Meaningful exit codes everywhere: `0` clean, `1` findings at/above
  `--fail-on` (`error`/`warning`/`any`/`never`), `2` usage error
- `--changed` and `--since REF` — scope findings to git-changed files
  (token-saving re-checks for agents)
- `--max-findings N` — truncate to the most severe findings; the summary
  still reflects the full scan and reports the omitted count
- `--report-file -` — write the markdown report to stdout
- Per-repo configuration via `.repomedic.toml` or `[tool.repomedic]` in
  pyproject.toml (analyzers, exclude, min_severity, max_findings, fail_on,
  include_tests)
- Language registry covering 30+ languages — detection, markdown fence
  hints, and per-language verify commands from one table
- New `shell` analyzer: `bash -n` syntax checks + ShellCheck integration
- New `hygiene` analyzer: oversized files, TODO/FIXME buildup, broken symlinks
- Config analyzer now syntax-checks all JSON/YAML/TOML files in the repo and
  flags missing README/LICENSE
- `repomedic run` now executes JavaScript, shell, Ruby, PHP, Perl, and Lua
  scripts (in addition to Python) with per-language failure parsing
- `repomedic agents` command + `docs/AGENTS.md` — self-describing agent
  integration guide
- `repomedic doctor`: per-toolchain checks (node, go, cargo, ruby, php),
  optional-tool status (semgrep/gitleaks/shellcheck), `--output json`, and
  exit 1 when required tools are missing
- `repomedic explain`: multi-ecosystem dependency listing (npm, cargo),
  language breakdown, `--output json|markdown`
- `repomedic fix --dry-run` and `--output json`
- `repomedic list-analyzers --output json`
- Report schema v2: `schema_version`, detected `languages` with file counts,
  `files_scanned`, `duration_seconds`, finding `fingerprint`s

### Changed
- Scans are non-interactive by default (all applicable analyzers, no
  prompts); the interactive picker moved behind `--interactive/-i`
- Machine outputs are clean: `--output json` prints only JSON on stdout;
  progress goes to stderr
- Analyzers now run in parallel (thread pool) — typical scans are 3-4x faster
- Scanner is side-effect free; doctor/explain no longer run (and print)
  during scans — commands split into collect/render layers
- Semgrep analyzer no longer emits a "not installed" finding on every scan;
  `repomedic doctor` surfaces optional tools instead

### Fixed
- `repomedic <subcommand>` no longer mis-parses the subcommand as a scan path
- Rust analyzer checked for Cargo.lock after `cargo check` had generated it,
  so the missing-lockfile finding could never fire on broken projects
- Untracked files inside new directories are now matched correctly in
  changed-file scans (`git status -uall`)
- `repomedic run` now exits 1 (not 0) when a script cannot be run at all —
  unsupported extension or missing interpreter — and prints the reason to
  stderr instead of silently reporting the project as healthy

## 0.1.0 (2026-03-15)

### Added
- Initial release
- 11 built-in analyzers: static, dependencies, git, config, runtime, logs, security, semgrep, javascript, golang, rust
- `repomedic` — main scan command with interactive analyzer picker
- `repomedic doctor` — development environment health check
- `repomedic explain` — plain-English project description
- `repomedic fix` — auto-fix common issues (Ruff, .gitignore, etc.)
- `repomedic run` — execute and analyze a Python script
- Rich terminal output with health score grading (A-F)
- Markdown fix report generation for AI coding agents
- JSON output for CI/CD integration
- GitHub URL support — clone and scan remote repos directly
- Multi-language detection (Python, JavaScript, Go, Rust)
- Severity filtering (`--min-severity`)
