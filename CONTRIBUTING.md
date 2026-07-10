# Contributing to RepoMedic

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/MBemera/repomedic.git
cd repomedic
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Development Workflow

1. **Create a branch** for your change:
   ```bash
   git checkout -b feature/my-change
   ```

2. **Make your changes** in `src/repomedic/`, `tests/`, or
   `editors/vscode/` as appropriate.

3. **Run tests** before submitting:
   ```bash
   pytest
   ```

4. **Lint your code**:
   ```bash
   ruff check src/ tests/
   ```

5. **Open a pull request** with a clear description of what you changed and why.

## VS Code Extension Development

The extension requires Node.js 22 and a local RepoMedic installation with the
debug extra:

```bash
pip install -e ".[debug]"
cd editors/vscode
npm ci --ignore-scripts
code .
```

Press `F5` to compile the extension and launch an Extension Development Host.
Before submitting extension changes, run:

```bash
npm test
npm audit --audit-level=high
```

`npm run package` creates a local VSIX for manual testing. Do not publish the
extension to the Marketplace as part of this phase.

Keep the extension's security boundaries intact: require Workspace Trust,
reject virtual workspaces, retain `--no-exec` as the default scan argument, use
argument arrays instead of shell command strings, and bound subprocess output
and diagnostic counts. Never place secrets in extension settings, logs,
fixtures, or packaged output.

## Adding a New Analyzer

RepoMedic uses a plugin-style analyzer system. To add a new one:

1. Create a new file in `src/repomedic/analyzers/` (e.g., `myanalyzer.py`)
2. Subclass `BaseAnalyzer` from `repomedic.analyzers.base`
3. Implement `name`, `description`, `is_applicable()`, and `analyze()`
4. Register it with the `@register` decorator from `repomedic.analyzers`
5. Import your module in `repomedic/analyzers/__init__.py`
6. Add tests in `tests/test_myanalyzer.py`

Example skeleton:

```python
from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult

@register
class MyAnalyzer(BaseAnalyzer):
    name = "myanalyzer"
    description = "Checks for something useful"

    def is_applicable(self, ctx: ScanContext) -> bool:
        # Return True if this analyzer should run on the given project
        return True

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        # Add findings to result.findings
        return result
```

## Code Style

- Python 3.11+
- Use type hints
- Follow existing patterns in the codebase
- Keep analyzer logic self-contained

## Reporting Issues

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Output of `repomedic doctor`
