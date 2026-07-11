"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  buildScanArguments,
  clampMaxFindings,
  executeRepoMedic,
  validateExecutable,
  validateExtraArguments,
} = require("../out/runner.js");

test("appends mandatory machine-output arguments after safe extras", () => {
  const metacharacters = "$(touch should-not-run); && still-one-argument";
  const args = buildScanArguments("/tmp/workspace", ["--no-exec", metacharacters], 25);

  assert.deepEqual(args, [
    "scan",
    "/tmp/workspace",
    "--no-exec",
    metacharacters,
    "--output",
    "json",
    "--max-findings",
    "25",
    "--fail-on",
    "never",
  ]);
});

test("rejects scan arguments that can override the extension contract", () => {
  assert.throws(() => validateExtraArguments(["--output=json"]), /cannot override/);
  assert.throws(() => validateExtraArguments(["--fail-on", "error"]), /cannot override/);
  assert.throws(() => validateExtraArguments(["--"]), /invalid argument/);
  assert.throws(() => validateExtraArguments(["bad\nargument"]), /invalid argument/);
  assert.throws(() => validateExtraArguments(["x".repeat(501)]), /short string/);
  assert.throws(() => validateExtraArguments("--no-exec"), /array of strings/);
});

test("accepts bare executable names and absolute paths only", () => {
  assert.equal(validateExecutable("repomedic"), "repomedic");
  assert.equal(validateExecutable(path.resolve("/opt/repomedic")), path.resolve("/opt/repomedic"));
  assert.throws(() => validateExecutable("./workspace-tool"), /must be absolute/);
  assert.throws(() => validateExecutable("bad\0tool"), /non-empty executable/);
});

test("bounds max findings", () => {
  assert.equal(clampMaxFindings(-1), 1);
  assert.equal(clampMaxFindings(10_000), 5_000);
  assert.equal(clampMaxFindings("many"), 200);
});

test("process failures never expose arguments or child stderr", async () => {
  const sensitiveArgument = "sensitive-argument-canary";

  await assert.rejects(
    executeRepoMedic(
      "repomedic-command-that-does-not-exist",
      [sensitiveArgument],
      process.cwd(),
    ),
    (error) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /could not start/);
      assert.ok(!error.message.includes(sensitiveArgument));
      return true;
    },
  );
});
