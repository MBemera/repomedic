import { execFile, type ExecFileException } from "node:child_process";
import * as path from "node:path";

const PROCESS_TIMEOUT_MS = 180_000;
const PROCESS_OUTPUT_LIMIT_BYTES = 10 * 1024 * 1024;
const MAX_EXTRA_ARGUMENTS = 32;
const MAX_EXTRA_ARGUMENT_CHARS = 500;
const MAX_EXECUTABLE_CHARS = 4_096;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const RESERVED_SCAN_ARGUMENTS = new Set([
  "--output",
  "-o",
  "--report-file",
  "-r",
  "--max-findings",
  "--fail-on",
]);

export interface ProcessOutput {
  stdout: string;
  exitCode: number;
}

export function buildScanArguments(
  workspaceRoot: string,
  extraArguments: unknown,
  maxFindings: unknown,
): string[] {
  return [
    "scan",
    workspaceRoot,
    ...validateExtraArguments(extraArguments),
    "--output",
    "json",
    "--max-findings",
    String(clampMaxFindings(maxFindings)),
    "--fail-on",
    "never",
  ];
}

export function validateExecutable(configuredValue: unknown): string {
  if (typeof configuredValue !== "string") {
    throw new Error("repomedic.path must be a string.");
  }
  const configured = configuredValue.trim();
  if (
    configured.length === 0 ||
    configured.length > MAX_EXECUTABLE_CHARS ||
    CONTROL_CHARACTERS.test(configured)
  ) {
    throw new Error("repomedic.path must be a non-empty executable name or absolute path.");
  }
  const containsSeparator = configured.includes("/") || configured.includes("\\");
  if (containsSeparator && !path.isAbsolute(configured)) {
    throw new Error("repomedic.path must be absolute when it contains path separators.");
  }
  return configured;
}

export function validateExtraArguments(configured: unknown): string[] {
  if (!Array.isArray(configured)) {
    throw new Error("repomedic.extraArgs must be an array of strings.");
  }
  if (configured.length > MAX_EXTRA_ARGUMENTS) {
    throw new Error(`repomedic.extraArgs accepts at most ${MAX_EXTRA_ARGUMENTS} entries.`);
  }
  return configured.map(validateExtraArgument);
}

export function clampMaxFindings(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    return 200;
  }
  return Math.min(5_000, Math.max(1, value));
}

export function executeRepoMedic(
  command: string,
  arguments_: string[],
  cwd: string,
): Promise<ProcessOutput> {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      arguments_,
      {
        cwd,
        encoding: "utf8",
        timeout: PROCESS_TIMEOUT_MS,
        maxBuffer: PROCESS_OUTPUT_LIMIT_BYTES,
        windowsHide: true,
        shell: false,
      },
      (error, stdout) => {
        const exitCode = typeof error?.code === "number" ? error.code : 0;
        if (error !== null && exitCode !== 1) {
          reject(new Error(processFailureMessage(error)));
          return;
        }
        resolve({ stdout, exitCode });
      },
    );
  });
}

function validateExtraArgument(value: unknown): string {
  if (typeof value !== "string" || value.length > MAX_EXTRA_ARGUMENT_CHARS) {
    throw new Error("Every repomedic.extraArgs entry must be a short string.");
  }
  if (value.length === 0 || CONTROL_CHARACTERS.test(value) || value === "--") {
    throw new Error("repomedic.extraArgs contains an invalid argument.");
  }
  const optionName = value.split("=", 1)[0] ?? "";
  if (RESERVED_SCAN_ARGUMENTS.has(optionName)) {
    throw new Error(`repomedic.extraArgs cannot override ${optionName}.`);
  }
  return value;
}

function processFailureMessage(error: ExecFileException): string {
  if (error.killed) {
    return "RepoMedic timed out or was terminated.";
  }
  if (typeof error.code === "number") {
    return `RepoMedic exited with code ${error.code}.`;
  }
  if (typeof error.code === "string" && /^[A-Z0-9_]+$/.test(error.code)) {
    return `RepoMedic could not start (${error.code}).`;
  }
  if (typeof error.signal === "string" && /^[A-Z0-9]+$/.test(error.signal)) {
    return `RepoMedic was terminated by ${error.signal}.`;
  }
  return "RepoMedic process failed.";
}
