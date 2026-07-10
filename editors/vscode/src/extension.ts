import * as path from "node:path";
import * as vscode from "vscode";

import { containedRegularFiles, isContainedRegularFile } from "./files";
import { DiagnosticData, mapReport, parseReport } from "./report";
import {
  buildScanArguments,
  clampMaxFindings,
  executeRepoMedic,
  validateExecutable,
} from "./runner";

let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let scanInProgress = false;

interface PythonTarget {
  uri: vscode.Uri;
  folder: vscode.WorkspaceFolder;
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("repomedic");
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  outputChannel = vscode.window.createOutputChannel("RepoMedic");
  statusBar.command = "repomedic.scanWorkspace";
  resetStatusBar();
  statusBar.show();

  context.subscriptions.push(
    diagnostics,
    statusBar,
    outputChannel,
    vscode.commands.registerCommand("repomedic.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("repomedic.debugCurrentFile", debugCurrentFile),
    vscode.commands.registerCommand("repomedic.clearDiagnostics", clearDiagnostics),
    vscode.commands.registerCommand("repomedic.captureCrashState", captureCrashState),
    vscode.languages.registerCodeActionsProvider(
      { language: "python" },
      new RepoMedicCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );
}

async function scanWorkspace(): Promise<void> {
  if (scanInProgress) {
    void vscode.window.showInformationMessage("A RepoMedic workspace scan is already running.");
    return;
  }
  scanInProgress = true;
  try {
    if (!(await requireTrustedWorkspace())) {
      return;
    }
    const folder = await selectedWorkspaceFolder();
    if (folder === undefined) {
      void vscode.window.showWarningMessage("Open a workspace before running RepoMedic.");
      return;
    }
    statusBar.text = "$(sync~spin) RepoMedic scanning";
    await runWorkspaceScan(folder);
  } catch {
    resetStatusBar();
    outputChannel.appendLine("[error] Workspace scan failed.");
    outputChannel.show(true);
    void vscode.window.showErrorMessage("RepoMedic scan failed. See the RepoMedic output channel.");
  } finally {
    scanInProgress = false;
  }
}

async function runWorkspaceScan(folder: vscode.WorkspaceFolder): Promise<void> {
  const maximumFindings = configuredMaxFindings(folder.uri);
  const result = await executeRepoMedic(
    repoMedicCommand(folder.uri),
    buildScanArguments(
      folder.uri.fsPath,
      configuredExtraArguments(folder.uri),
      maximumFindings,
    ),
    folder.uri.fsPath,
  );
  const mapped = mapReport(parseReport(result.stdout), folder.uri.fsPath, maximumFindings);
  const safeDiagnostics = await containedFileDiagnostics(
    mapped.diagnostics,
    folder.uri.fsPath,
  );
  applyDiagnostics(folder, safeDiagnostics);
  showHealth(mapped.healthScore, mapped.healthGrade, mapped.analyzersFailed);
  showScanResult(safeDiagnostics.length, mapped.analyzersFailed);
}

function applyDiagnostics(
  folder: vscode.WorkspaceFolder,
  mappedDiagnostics: DiagnosticData[],
): void {
  const grouped = new Map<string, { uri: vscode.Uri; items: vscode.Diagnostic[] }>();
  for (const mapped of mappedDiagnostics) {
    const uri = diagnosticUri(folder, mapped.filePath);
    const key = uri.toString();
    const group = grouped.get(key) ?? { uri, items: [] };
    group.items.push(toVsCodeDiagnostic(mapped));
    grouped.set(key, group);
  }
  diagnostics.clear();
  diagnostics.set([...grouped.values()].map((group) => [group.uri, group.items]));
}

function diagnosticUri(folder: vscode.WorkspaceFolder, filePath: string): vscode.Uri {
  const relativePath = path.relative(folder.uri.fsPath, filePath);
  return vscode.Uri.joinPath(folder.uri, ...relativePath.split(path.sep));
}

function toVsCodeDiagnostic(mapped: DiagnosticData): vscode.Diagnostic {
  const range = new vscode.Range(
    mapped.startLine,
    mapped.startColumn,
    mapped.endLine,
    mapped.endColumn,
  );
  const diagnostic = new vscode.Diagnostic(
    range,
    mapped.message,
    mapped.severity as vscode.DiagnosticSeverity,
  );
  diagnostic.code = mapped.code;
  diagnostic.source = mapped.source;
  return diagnostic;
}

async function debugCurrentFile(candidate?: vscode.Uri): Promise<void> {
  if (!(await requireTrustedWorkspace())) {
    return;
  }
  const target = await selectedPythonTarget(candidate, "starting RepoMedic debugging");
  if (target === undefined) {
    return;
  }
  let started = false;
  try {
    started = await vscode.debug.startDebugging(target.folder, debugConfiguration(target));
  } catch {
    showCommandFailure("Python debugging");
    return;
  }
  if (!started) {
    void vscode.window.showErrorMessage("VS Code could not start the Python debugger.");
    return;
  }
  const choice = await vscode.window.showInformationMessage(
    "Interactive debugging started.",
    "Capture crash state",
  );
  if (choice === "Capture crash state") {
    await captureCrashState(target.uri);
  }
}

async function captureCrashState(candidate?: vscode.Uri): Promise<void> {
  if (!(await requireTrustedWorkspace())) {
    return;
  }
  const target = await selectedPythonTarget(candidate, "capturing crash state");
  if (target === undefined) {
    return;
  }
  try {
    await vscode.tasks.executeTask(crashCaptureTask(target));
  } catch {
    showCommandFailure("Crash-state capture");
  }
}

function crashCaptureTask(target: PythonTarget): vscode.Task {
  const execution = new vscode.ProcessExecution(
    repoMedicCommand(target.folder.uri),
    ["debug", target.uri.fsPath, "--output", "markdown"],
    { cwd: target.folder.uri.fsPath },
  );
  const task = new vscode.Task(
    { type: "repomedic", task: "captureCrashState" },
    target.folder,
    "Capture crash state",
    "RepoMedic",
    execution,
  );
  task.presentationOptions = {
    reveal: vscode.TaskRevealKind.Always,
    panel: vscode.TaskPanelKind.Dedicated,
    clear: true,
  };
  return task;
}

function debugConfiguration(target: PythonTarget): vscode.DebugConfiguration {
  return {
    name: "RepoMedic: Debug current file",
    type: "debugpy",
    request: "launch",
    program: target.uri.fsPath,
    cwd: target.folder.uri.fsPath,
    console: "integratedTerminal",
    justMyCode: true,
  };
}

function clearDiagnostics(): void {
  diagnostics.clear();
  resetStatusBar();
}

class RepoMedicCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const related = context.diagnostics.filter((item) => item.source === "repomedic");
    if (related.length === 0 || path.extname(document.uri.fsPath).toLowerCase() !== ".py") {
      return [];
    }
    return [
      commandAction(
        "Debug this finding",
        "repomedic.debugCurrentFile",
        document.uri,
        related,
      ),
      commandAction(
        "Capture crash state",
        "repomedic.captureCrashState",
        document.uri,
        related,
      ),
    ];
  }
}

function commandAction(
  title: string,
  command: string,
  uri: vscode.Uri,
  related: vscode.Diagnostic[],
): vscode.CodeAction {
  const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
  action.command = { title, command, arguments: [uri] };
  action.diagnostics = related;
  return action;
}

async function selectedWorkspaceFolder(): Promise<vscode.WorkspaceFolder | undefined> {
  const activeUri = vscode.window.activeTextEditor?.document.uri;
  if (activeUri !== undefined) {
    const activeFolder = vscode.workspace.getWorkspaceFolder(activeUri);
    if (activeFolder !== undefined) {
      return activeFolder;
    }
  }
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 1) {
    return folders[0];
  }
  if (folders.length > 1) {
    return vscode.window.showWorkspaceFolderPick({
      placeHolder: "Select the workspace folder to scan with RepoMedic",
    });
  }
  return undefined;
}

async function selectedPythonTarget(
  candidate: vscode.Uri | undefined,
  action: string,
): Promise<PythonTarget | undefined> {
  const uri = candidate ?? vscode.window.activeTextEditor?.document.uri;
  const folder = uri === undefined ? undefined : vscode.workspace.getWorkspaceFolder(uri);
  const isPython = uri !== undefined && path.extname(uri.fsPath).toLowerCase() === ".py";
  if (uri === undefined || folder === undefined || !isPython) {
    void vscode.window.showWarningMessage(
      `Open a Python file inside a workspace before ${action}.`,
    );
    return undefined;
  }
  if (!(await isContainedRegularFile(folder.uri.fsPath, uri.fsPath))) {
    void vscode.window.showWarningMessage(
      "The selected Python file must resolve to a regular file inside its workspace.",
    );
    return undefined;
  }
  return { uri, folder };
}

async function containedFileDiagnostics(
  mappedDiagnostics: DiagnosticData[],
  workspaceRoot: string,
): Promise<DiagnosticData[]> {
  const filePaths = mappedDiagnostics.map((diagnostic) => diagnostic.filePath);
  const safePaths = new Set(await containedRegularFiles(workspaceRoot, filePaths));
  return mappedDiagnostics.filter((diagnostic) => safePaths.has(diagnostic.filePath));
}

async function requireTrustedWorkspace(): Promise<boolean> {
  if (vscode.workspace.isTrusted) {
    return true;
  }
  await vscode.window.showWarningMessage(
    "RepoMedic commands are disabled until this workspace is trusted.",
  );
  return false;
}

function repoMedicCommand(resource: vscode.Uri): string {
  const configured = vscode.workspace
    .getConfiguration("repomedic", resource)
    .get<unknown>("path", "repomedic");
  return validateExecutable(configured);
}

function configuredExtraArguments(resource: vscode.Uri): unknown {
  return vscode.workspace
    .getConfiguration("repomedic", resource)
    .get<unknown>("extraArgs", ["--no-exec"]);
}

function configuredMaxFindings(resource: vscode.Uri): number {
  const configured = vscode.workspace
    .getConfiguration("repomedic", resource)
    .get<unknown>("maxFindings", 200);
  return clampMaxFindings(configured);
}

function showHealth(score: number, grade: string, analyzersFailed: number): void {
  const icon = analyzersFailed > 0 ? "$(warning)" : "$(pulse)";
  const failed = analyzersFailed > 0 ? ` · ${analyzersFailed} failed` : "";
  statusBar.text = `${icon} RepoMedic ${score}/100 (${grade})${failed}`;
  statusBar.tooltip =
    analyzersFailed > 0
      ? "RepoMedic scan was partial because one or more analyzers failed."
      : "RepoMedic workspace health. Click to scan again.";
}

function resetStatusBar(): void {
  statusBar.text = "$(pulse) RepoMedic";
  statusBar.tooltip = "Click to scan this workspace with RepoMedic.";
}

function showScanResult(findingCount: number, analyzersFailed: number): void {
  const message = `RepoMedic found ${findingCount} file finding(s).`;
  if (analyzersFailed === 0) {
    void vscode.window.showInformationMessage(message);
    return;
  }
  void vscode.window.showWarningMessage(
    `${message} ${analyzersFailed} analyzer(s) failed, so the scan is partial.`,
  );
}

function showCommandFailure(operation: string): void {
  outputChannel.appendLine(`[error] ${operation} failed.`);
  outputChannel.show(true);
  void vscode.window.showErrorMessage(`${operation} failed. See the RepoMedic output channel.`);
}
