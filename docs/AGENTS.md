# RepoMedic for Coding Agents

RepoMedic is a **bug sniffer** built to be operated by AI coding agents. One
command diagnoses a repo across 13 analyzers and returns a compact, structured
fix report — so you spend your tokens fixing bugs, not hunting for them.

> Self-discovery: run `repomedic agents` in any shell to print a compact
> version of this guide.

## TL;DR

```bash
repomedic sniff <path>
```

- **Non-interactive.** Never prompts. Safe to run unattended.
- **Markdown fix report on stdout.** Progress/status goes to stderr, so piping
  or capturing stdout gives you the report and nothing else.
- **Exit code is the verdict:** `0` = no errors, `1` = errors found, `2` = usage error.
- **Bounded output:** defaults to the 50 most severe findings (`--max-findings` to change).

## The fix report format

```markdown
---
tool: repomedic
schema: 2
generated: 2026-07-07T12:00:00+00:00
target: /path/to/project
health: 62/100 (D)
errors: 3
warnings: 5
infos: 2
shown: 10
omitted: 0
languages: python (24), typescript (9)
---

# RepoMedic Fix Report
...
## Findings by File

### `src/app.py` — 1 error, 2 warnings

#### RM-105466e2 `STATIC-001` error — Syntax error (line 4) `[python]`

invalid syntax

**Fix:** Fix the syntax error: invalid syntax

```python
  2 | import json
  3 |
> 4 | def broken(:
  5 |     pass
```
```

What to rely on:

- **Front matter** is machine-readable `key: value` — parse it to decide
  whether to read further (`errors: 0` and `omitted: 0` means nothing to fix).
- **Findings are grouped by file**, files with errors first, project-level
  findings last. Fix one file at a time.
- **`RM-xxxxxxxx` fingerprints are stable across runs** for unchanged
  findings — use them to track what you fixed and to diff scans.
- **Snippets** show the offending lines (`>` marks the finding line), so you
  usually don't need to open the file to understand the problem.
- **"Verify after fixing"** lists exact commands to confirm your fixes,
  including a `repomedic sniff … --fail-on error` re-run.
- **"Analyzer failures"** (if present) lists analyzers that crashed — their
  findings are missing, so don't treat the report as exhaustive.

## Token-saving workflow

```bash
# 1. Get the prioritized fix list (bounded output)
repomedic sniff . --max-findings 30

# 2. Fix findings file by file (snippets usually suffice)

# 3. Re-check only what you touched — much smaller report
repomedic sniff . --changed --fail-on error

# 4. Exit code 0 → done. Report the RM- IDs you fixed.
```

`--changed` scopes the report to git-modified/untracked files;
`--since <ref>` scopes to files changed since a ref (e.g. `--since HEAD~3`,
`--since origin/main`). Project-level findings are always kept.

## All commands

| Command | Purpose | Default output |
|---|---|---|
| `repomedic sniff [PATH]` | Bug-sniff for agents | markdown → stdout, `--fail-on error` |
| `repomedic [PATH]` / `repomedic scan [PATH]` | Full scan | rich terminal UI, `--fail-on never` |
| `repomedic run SCRIPT [ARGS…]` | Execute a script (`.py .js .mjs .cjs .sh .bash .rb .php .pl .lua`) and analyze the failure | JSON |
| `repomedic doctor [PATH]` | Environment/toolchain health (exit 1 if something required is missing) | rich; `-o json` |
| `repomedic explain [PATH]` | Project brief: type, languages, dependencies | rich; `-o markdown` / `-o json` |
| `repomedic fix [PATH]` | Safe auto-fixes (ruff --fix, .gitignore, .env.example) | rich; `--dry-run`, `-o json` |
| `repomedic list-analyzers` | List analyzers | rich; `-o json` |
| `repomedic agents` | Print the agent cheat sheet | markdown |

## Flags that matter (scan and sniff)

| Flag | Effect |
|---|---|
| `-a, --analyzers a,b,c` | Restrict to specific analyzers |
| `-s, --min-severity LEVEL` | Drop findings below `error`/`warning`/`info` |
| `--max-findings N` | Keep the N most severe findings; the report states how many were omitted (`0` = unlimited) |
| `--fail-on LEVEL` | Exit 1 when findings at/above `error`/`warning`/`any`; `never` disables |
| `--changed` / `--since REF` | Scope findings to git-changed files |
| `-r, --report-file PATH` | Write markdown report to PATH (`-` = stdout) |
| `--no-snippets` | Omit code snippets (smaller report) |
| `-o, --output FORMAT` | `rich`, `json`, or `markdown` (scan only; sniff is always markdown) |

## JSON mode

`repomedic <path> --output json` prints a single JSON document to stdout
(schema_version 2): summary counts, health score, per-analyzer findings with
fingerprints, detected languages, timings. Use it when you want to post-process
findings programmatically instead of reading markdown.

## Per-repo defaults

Drop a `.repomedic.toml` at the repo root (or use `[tool.repomedic]` in
`pyproject.toml`) to pin scan behavior for every invocation:

```toml
analyzers = ["static", "git", "security", "config"]
exclude = ["migrations", "vendor"]   # extra ignored directories
min_severity = "warning"
max_findings = 50
fail_on = "error"
include_tests = false
```

CLI flags always override the config file.

## Exit codes (contract)

| Code | Meaning |
|---|---|
| `0` | Scan completed; nothing at/above the `--fail-on` threshold |
| `1` | Findings at/above the threshold (for `sniff`: errors exist) |
| `2` | Usage error — bad path, unknown analyzer, invalid flag value |

`repomedic run` exits `1` when the script failed to run (unsupported
extension, missing interpreter) or ran with errors, and `0` when it ran
cleanly. `repomedic doctor` exits `1` when a required tool/dependency is missing.
