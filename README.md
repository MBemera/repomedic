# RepoMedic

**AI-agent repo debugging system — diagnose issues in any folder or repo from the command line.**

RepoMedic scans your codebase, identifies problems, and generates structured fix reports that you can hand directly to an AI coding agent. Think of it as a doctor for your repository: it checks vitals, runs diagnostics, explains what it finds, and prescribes fixes.

![Scan Results](docs/screenshots/scan-results.png)

---

## Why

Debugging a broken or messy repo is time-consuming. You bounce between linters, dependency checks, git logs, and config files trying to piece together what's wrong. AI coding agents can help fix things, but they need concise, structured context to be effective.

RepoMedic bridges that gap. It runs **11 analyzers** across your project in seconds, produces a health score, and outputs a Markdown fix report designed to be copy-pasted straight into an AI agent's context window — no manual triage needed.

## What

RepoMedic is a Python CLI tool that performs automated diagnostics on local directories and GitHub repos. It covers:

| Analyzer | What It Checks |
|---|---|
| **Static Analysis** | Linting issues via Ruff (Python) |
| **Dependencies** | Missing, outdated, or broken packages |
| **Git Health** | Merge conflicts, large files, uncommitted changes |
| **Config** | Missing `.gitignore`, broken `pyproject.toml`, missing configs |
| **Runtime** | Execute a script and capture tracebacks/errors |
| **Log Analysis** | Parse log files for errors and patterns |
| **Security** | Exposed secrets, `.env` files, hardcoded credentials |
| **Semgrep** | Advanced static analysis patterns (if Semgrep is installed) |
| **JavaScript** | ESLint issues, missing `node_modules`, lockfile conflicts |
| **Go** | `go vet`, build errors, module issues |
| **Rust** | `cargo check`, Clippy warnings, build failures |

### Commands

| Command | What It Does |
|---|---|
| `repomedic .` | Scan a directory with interactive analyzer picker |
| `repomedic doctor` | Check your dev environment (Python, git, pip, dependencies) |
| `repomedic explain` | Describe a project in plain English |
| `repomedic fix` | Auto-fix safe, common issues (Ruff, `.gitignore`, etc.) |
| `repomedic run script.py` | Run a Python script and analyze its output |

### Output Formats

- **Rich** (default) — Colorful terminal tables with a health score grade (A-F)
- **Markdown** — Structured fix report for AI agents, with file paths, problem descriptions, and suggested fixes
- **JSON** — Machine-readable output for CI/CD or tool integration

## How

### Install

```bash
git clone https://github.com/YOUR_USERNAME/repomedic.git
cd repomedic
pip install -e .
```

Requires **Python 3.11+**. Core dependencies: `typer`, `pydantic`, `rich`.

### Quick Start

```bash
# Scan the current directory (interactive analyzer picker)
repomedic

# Scan with all analyzers, no prompts
repomedic . --all

# Scan a GitHub repo directly
repomedic https://github.com/user/repo

# Pick specific analyzers
repomedic . --analyzers static,git,security

# Only show warnings and errors
repomedic . --min-severity warning

# Output as Markdown fix report
repomedic . --output markdown

# Output as JSON
repomedic . --output json
```

### Screenshots

#### Scan Results

Health score, categorized findings (errors/warnings/tips), and actionable next steps:

![Scan Results](docs/screenshots/scan-results.png)

#### Doctor — Environment Health Check

Checks Python, git, pip, virtual environments, and project dependencies:

![Doctor](docs/screenshots/doctor.png)

#### Explain — Project Overview

Describes what a project is, what it uses, and how it's organized:

![Explain](docs/screenshots/explain.png)

#### Fix Report — AI Agent Output

Generates a self-contained Markdown report that you feed to your AI coding agent:

![Fix Report](docs/screenshots/fix-report.png)

### Feed Fixes to an AI Agent

```bash
# Generate the fix report
repomedic . --output markdown

# The report is saved to ./repomedic-fixes.md
# Hand it to your AI coding agent:
cat repomedic-fixes.md | your-ai-agent
```

Each fix entry contains the file path, line number, problem description, and suggested solution — so your AI agent can apply fixes without needing to understand the entire codebase.

## Project Structure

```
src/repomedic/
├── cli.py                # Typer CLI entry point
├── models.py             # Pydantic models (Finding, ScanReport, etc.)
├── core/
│   ├── scanner.py        # Orchestrator — runs analyzers, builds reports
│   └── context.py        # ScanContext — language detection, file discovery
├── analyzers/
│   ├── base.py           # BaseAnalyzer interface
│   ├── static.py         # Ruff / linting
│   ├── dependencies.py   # Dependency health
│   ├── git.py            # Git repo health
│   ├── config.py         # Project config files
│   ├── runtime.py        # Script execution analysis
│   ├── logs.py           # Log file parsing
│   ├── security.py       # Secret/credential detection
│   ├── semgrep.py        # Semgrep integration
│   ├── javascript.py     # JS/Node analysis
│   ├── golang.py         # Go analysis
│   └── rust.py           # Rust/Cargo analysis
├── commands/
│   ├── doctor.py         # Environment health checks
│   ├── explain.py        # Project explanation generator
│   └── fix.py            # Auto-fixer
├── output/
│   ├── rich_output.py    # Terminal table output
│   ├── markdown_output.py# AI-agent fix reports
│   └── json_output.py    # JSON output
└── utils/
    ├── process.py        # Subprocess runner
    └── fs.py             # File system helpers
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/
```

## License

MIT
