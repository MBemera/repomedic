# Changelog

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
