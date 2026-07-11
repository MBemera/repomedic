import * as path from "node:path";

const REPORT_SCHEMA_VERSION = 3;
const MAX_DIAGNOSTIC_MESSAGE_CHARS = 2_000;
const MAX_DIAGNOSTIC_CODE_CHARS = 80;
const MAX_DIAGNOSTIC_POSITION = 2_147_483_646;
const MAX_REPORT_PATH_CHARS = 4_096;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u0009\u000b-\u001f\u007f]/g;
const FINDING_SEVERITIES = new Set(["error", "warning", "info"]);

type JsonRecord = Record<string, unknown>;

export type DiagnosticSeverityValue = 0 | 1 | 2;

export interface DiagnosticData {
  filePath: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  severity: DiagnosticSeverityValue;
  code: string;
  message: string;
  source: "repomedic";
}

export interface MappedReport {
  diagnostics: DiagnosticData[];
  healthScore: number;
  healthGrade: string;
  analyzersFailed: number;
}

export interface RepoMedicReport {
  schema_version: number;
  summary: JsonRecord;
  results: JsonRecord[];
}

export function parseReport(rawReport: string): RepoMedicReport {
  const parsed: unknown = JSON.parse(rawReport);
  if (!isRecord(parsed)) {
    throw new Error("RepoMedic returned a non-object JSON payload.");
  }
  if (parsed.schema_version !== REPORT_SCHEMA_VERSION) {
    throw new Error(`Unsupported RepoMedic schema: ${String(parsed.schema_version)}`);
  }
  if (!Array.isArray(parsed.results) || !parsed.results.every(isRecord)) {
    throw new Error("RepoMedic report results are malformed.");
  }
  if (!parsed.results.every(hasValidAnalyzerResult)) {
    throw new Error("RepoMedic report findings are malformed.");
  }
  if (!isValidSummary(parsed.summary, parsed.results)) {
    throw new Error("RepoMedic report summary is malformed.");
  }
  return {
    schema_version: REPORT_SCHEMA_VERSION,
    summary: parsed.summary,
    results: parsed.results,
  };
}

export function mapReport(
  report: RepoMedicReport,
  workspaceRoot: string,
  maxFindings: number,
): MappedReport {
  const limit = clampInteger(maxFindings, 1, 5_000, 200);
  const diagnostics: DiagnosticData[] = [];
  for (const finding of reportFindings(report)) {
    const diagnostic = mapFinding(finding, workspaceRoot);
    if (diagnostic !== undefined) {
      diagnostics.push(diagnostic);
    }
    if (diagnostics.length >= limit) {
      break;
    }
  }
  return {
    diagnostics,
    healthScore: healthScore(report.summary),
    healthGrade: healthGrade(report.summary),
    analyzersFailed: integerValue(report.summary.analyzers_failed, 0),
  };
}

function reportFindings(report: RepoMedicReport): JsonRecord[] {
  const findings: JsonRecord[] = [];
  for (const result of report.results) {
    if (!Array.isArray(result.findings)) {
      continue;
    }
    findings.push(...result.findings.filter(isRecord));
  }
  return findings;
}

function mapFinding(
  finding: JsonRecord,
  workspaceRoot: string,
): DiagnosticData | undefined {
  const candidatePath = stringValue(finding.file_path);
  const filePath = resolveContainedPath(workspaceRoot, candidatePath);
  if (filePath === undefined) {
    return undefined;
  }
  const startLine = boundedPosition(finding.line);
  const startColumn = boundedPosition(finding.column);
  return {
    filePath,
    startLine,
    startColumn,
    endLine: startLine,
    endColumn: startColumn + 1,
    severity: severityValue(finding.severity),
    code: cleanText(stringValue(finding.code), MAX_DIAGNOSTIC_CODE_CHARS),
    message: findingMessage(finding),
    source: "repomedic",
  };
}

function resolveContainedPath(
  workspaceRoot: string,
  candidatePath: string,
): string | undefined {
  if (candidatePath.length === 0 || candidatePath.includes("\0")) {
    return undefined;
  }
  if (path.isAbsolute(candidatePath)) {
    return undefined;
  }
  const root = path.resolve(workspaceRoot);
  const resolved = path.resolve(root, candidatePath);
  const relative = path.relative(root, resolved);
  if (relative.length === 0) {
    return undefined;
  }
  if (relative === ".." || relative.startsWith(`..${path.sep}`)) {
    return undefined;
  }
  if (path.isAbsolute(relative)) {
    return undefined;
  }
  return resolved;
}

function findingMessage(finding: JsonRecord): string {
  const title = stringValue(finding.title);
  const description = stringValue(finding.description);
  const combined = description.length > 0 ? `${title}\n${description}` : title;
  return cleanText(combined || "RepoMedic finding", MAX_DIAGNOSTIC_MESSAGE_CHARS);
}

function severityValue(value: unknown): DiagnosticSeverityValue {
  if (value === "error") {
    return 0;
  }
  if (value === "warning") {
    return 1;
  }
  return 2;
}

function healthScore(summary: JsonRecord): number {
  return clampInteger(summary.health_score, 0, 100, 100);
}

function healthGrade(summary: JsonRecord): string {
  const grade = cleanText(stringValue(summary.health_grade), 2);
  return grade || "A";
}

function cleanText(value: string, maximumLength: number): string {
  const safeText = value.replace(UNSAFE_TEXT_CONTROL_CHARACTERS, "");
  if (safeText.length <= maximumLength) {
    return safeText;
  }
  return `${safeText.slice(0, maximumLength - 1)}…`;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function integerValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) ? value : fallback;
}

function boundedPosition(value: unknown): number {
  return clampInteger(value, 1, MAX_DIAGNOSTIC_POSITION + 1, 1) - 1;
}

function clampInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  fallback: number,
): number {
  const integer = integerValue(value, fallback);
  return Math.min(maximum, Math.max(minimum, integer));
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasValidAnalyzerResult(result: JsonRecord): boolean {
  if (!isValidAnalyzerError(result.error) || !Array.isArray(result.findings)) {
    return false;
  }
  return result.findings.every(isValidFinding);
}

function isValidFinding(value: unknown): value is JsonRecord {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isFindingSeverity(value.severity) &&
    typeof value.code === "string" &&
    value.code.length > 0 &&
    typeof value.title === "string" &&
    typeof value.description === "string" &&
    isValidReportPath(value.file_path) &&
    isValidOptionalPosition(value.line) &&
    isValidOptionalPosition(value.column)
  );
}

function isFindingSeverity(value: unknown): value is string {
  return typeof value === "string" && FINDING_SEVERITIES.has(value);
}

function isValidReportPath(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  if (value.length > MAX_REPORT_PATH_CHARS || CONTROL_CHARACTERS.test(value)) {
    return false;
  }
  const normalized = path.normalize(value);
  return (
    normalized !== "." &&
    normalized !== ".." &&
    !normalized.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(normalized)
  );
}

function isValidOptionalPosition(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= MAX_DIAGNOSTIC_POSITION + 1
  );
}

function isValidAnalyzerError(value: unknown): boolean {
  return value === undefined || value === null || typeof value === "string";
}

function isValidSummary(value: unknown, results: JsonRecord[]): value is JsonRecord {
  if (!isRecord(value)) {
    return false;
  }
  const score = value.health_score;
  const grade = value.health_grade;
  const failed = value.analyzers_failed;
  const countedFailures = results.filter(hasAnalyzerFailure).length;
  return (
    typeof score === "number" &&
    Number.isInteger(score) &&
    score >= 0 &&
    score <= 100 &&
    typeof grade === "string" &&
    /^[A-F]$/.test(grade) &&
    typeof failed === "number" &&
    Number.isInteger(failed) &&
    failed === countedFailures
  );
}

function hasAnalyzerFailure(result: JsonRecord): boolean {
  return typeof result.error === "string" && result.error.length > 0;
}
