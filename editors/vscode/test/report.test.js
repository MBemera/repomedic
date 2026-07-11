"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const { mapReport, parseReport } = require("../out/report.js");

function reportWith(findings, summary = {}) {
  return {
    schema_version: 3,
    summary: {
      health_score: 82,
      health_grade: "B",
      analyzers_failed: 0,
      ...summary,
    },
    results: [{ analyzer: "test", error: null, findings }],
  };
}

test("maps findings to contained zero-based diagnostics", () => {
  const root = path.resolve("/tmp/repomedic-workspace");
  const report = parseReport(
    JSON.stringify(
      reportWith([
        {
          severity: "error",
          code: "STATIC-001",
          title: "Syntax error",
          description: "invalid syntax",
          file_path: "src/app.py",
          line: 4,
          column: 3,
        },
        {
          severity: "warning",
          code: "CONFIG-001",
          title: "Config warning",
          description: "",
          file_path: "config.json",
          line: 1,
        },
      ]),
    ),
  );

  const mapped = mapReport(report, root, 20);

  assert.equal(mapped.healthScore, 82);
  assert.equal(mapped.healthGrade, "B");
  assert.equal(mapped.diagnostics.length, 2);
  assert.deepEqual(mapped.diagnostics[0], {
    filePath: path.join(root, "src/app.py"),
    startLine: 3,
    startColumn: 2,
    endLine: 3,
    endColumn: 3,
    severity: 0,
    code: "STATIC-001",
    message: "Syntax error\ninvalid syntax",
    source: "repomedic",
  });
  assert.equal(mapped.diagnostics[1].severity, 1);
});

test("rejects project-level and escaping paths", () => {
  const root = path.resolve("/tmp/repomedic-workspace");
  const report = reportWith([
    { severity: "error", code: "PROJECT", title: "Project finding" },
    {
      severity: "error",
      code: "ESCAPE",
      title: "Escape",
      file_path: "../outside.py",
      line: 1,
    },
    {
      severity: "error",
      code: "ROOT",
      title: "Root directory",
      file_path: ".",
      line: 1,
    },
    {
      severity: "error",
      code: "ABSOLUTE",
      title: "Absolute path",
      file_path: path.join(root, "inside.py"),
      line: 1,
    },
  ]);

  assert.deepEqual(mapReport(report, root, 20).diagnostics, []);
});

test("bounds count, positions, text, score, and unknown severity", () => {
  const root = path.resolve("/tmp/repomedic-workspace");
  const longTitle = `bad\0\u001b${"x".repeat(2_100)}`;
  const report = reportWith(
    [
      {
        severity: "info",
        code: "X".repeat(100),
        title: longTitle,
        file_path: "one.py",
        line: Number.MAX_SAFE_INTEGER,
        column: -2,
      },
      { severity: "error", code: "SECOND", title: "second", file_path: "two.py" },
    ],
    { health_score: 500, health_grade: "TOO-LONG" },
  );

  const mapped = mapReport(report, root, 1);

  assert.equal(mapped.diagnostics.length, 1);
  assert.equal(mapped.diagnostics[0].severity, 2);
  assert.equal(mapped.diagnostics[0].startLine, 2_147_483_646);
  assert.equal(mapped.diagnostics[0].startColumn, 0);
  assert.equal(mapped.diagnostics[0].code.length, 80);
  assert.equal(mapped.diagnostics[0].message.length, 2_000);
  assert.ok(!mapped.diagnostics[0].message.includes("\0"));
  assert.ok(!mapped.diagnostics[0].message.includes("\u001b"));
  assert.equal(mapped.healthScore, 100);
  assert.equal(mapped.healthGrade, "T…");
});

test("rejects malformed and unsupported reports", () => {
  assert.throws(() => parseReport("not-json"), /JSON/);
  assert.throws(() => parseReport("[]"), /non-object/);
  assert.throws(
    () => parseReport(JSON.stringify({ schema_version: 2, results: [] })),
    /Unsupported RepoMedic schema/,
  );
  assert.throws(
    () => parseReport(JSON.stringify({ schema_version: 3, results: "bad" })),
    /results are malformed/,
  );
  assert.throws(
    () => parseReport(JSON.stringify({ schema_version: 3, results: [], summary: {} })),
    /summary is malformed/,
  );
  assert.throws(
    () =>
      parseReport(
        JSON.stringify({
          schema_version: 3,
          summary: { health_score: 100, health_grade: "A", analyzers_failed: 0 },
          results: [{ findings: "bad" }],
        }),
      ),
    /findings are malformed/,
  );
  assert.throws(
    () =>
      parseReport(
        JSON.stringify(
          reportWith([
            {
              severity: "catastrophic",
              code: "BAD-SEVERITY",
              title: "Bad severity",
              description: "invalid",
              file_path: "app.py",
              line: 1,
            },
          ]),
        ),
      ),
    /findings are malformed/,
  );
  assert.throws(
    () =>
      parseReport(
        JSON.stringify(
          reportWith([
            {
              severity: "error",
              code: 7,
              title: null,
              description: "invalid",
              file_path: "../outside.py",
              line: 0,
            },
          ]),
        ),
      ),
    /findings are malformed/,
  );
});

test("surfaces analyzer failure counts without retaining error text", () => {
  const report = reportWith([], {
    health_score: 100,
    health_grade: "A",
    analyzers_failed: 1,
  });
  report.results[0].error = "untrusted-error-canary-must-not-be-rendered";

  const mapped = mapReport(parseReport(JSON.stringify(report)), "/tmp/workspace", 20);

  assert.equal(mapped.analyzersFailed, 1);
  assert.ok(!JSON.stringify(mapped).includes("must-not-be-rendered"));
});
