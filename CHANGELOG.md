# Changelog

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
