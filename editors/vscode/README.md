# RepoMedic for VS Code

This development extension runs RepoMedic against a trusted workspace, maps
schema-version 3 findings into the Problems panel, and exposes Python debugging
and crash-state capture actions. It is not published to the VS Code Marketplace.

## Prerequisites

- VS Code 1.92 or newer
- Node.js 22
- Python 3.11 or newer
- The Microsoft Python Debugger extension (`ms-python.debugpy`)
- RepoMedic installed with debugger support

From the repository root:

```bash
pip install -e ".[debug]"
cd editors/vscode
npm ci --ignore-scripts
```

Open `editors/vscode/` as the VS Code workspace and press `F5`. The launch
configuration compiles the TypeScript before opening an Extension Development
Host.

## Commands

- **RepoMedic: Scan Workspace** runs a bounded JSON scan and replaces RepoMedic
  diagnostics only after the full report validates.
- **RepoMedic: Debug Current File** launches the active Python file with
  `debugpy` and offers bounded RepoMedic crash-state capture.
- **RepoMedic: Clear Diagnostics** removes RepoMedic diagnostics and resets the
  health status.

Python diagnostics also provide quick fixes for interactive debugging and
crash-state capture.

## Settings

| Setting | Default | Scope | Purpose |
| --- | --- | --- | --- |
| `repomedic.path` | `repomedic` | Machine | Executable name or absolute executable path |
| `repomedic.extraArgs` | `["--no-exec"]` | Machine | Additional scan arguments; output-contract overrides are rejected |
| `repomedic.maxFindings` | `200` | Resource | Problems-panel diagnostic limit, bounded from 1 to 5,000 |

The extension does not pass `repomedic.extraArgs` to debugger commands.

## Security Boundaries

The extension is disabled in untrusted and virtual workspaces. Scans use
Node's `execFile` with an argument array and `shell: false`; crash capture uses
VS Code `ProcessExecution`. Process time, output, arguments, diagnostic text,
locations, and count are bounded. Reported file paths must remain inside the
selected workspace.

`--no-exec` is the safe scan default. Remove it only when you deliberately want
RepoMedic to run repo-controlled toolchains in code you trust. Debugging and
crash capture execute the selected Python file, so use development credentials
with narrow permissions and never debug untrusted code.

## Verification and Packaging

```bash
npm test
npm audit --audit-level=high
npm run package
```

`npm run package` creates a local VSIX for manual testing. Marketplace
publishing is outside this phase.
