"use strict";

const assert = require("node:assert/strict");
const { mkdir, mkdtemp, rm, symlink, writeFile } = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  containedRegularFiles,
  isContainedRegularFile,
} = require("../out/files.js");

test("rejects missing, directory, and escaping symlink targets", async () => {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "repomedic-vscode-"));
  const workspaceRoot = path.join(fixtureRoot, "workspace");
  const insideFile = path.join(workspaceRoot, "inside.py");
  const outsideFile = path.join(fixtureRoot, "outside.py");
  const outsideLink = path.join(workspaceRoot, "outside-link.py");
  const insideLink = path.join(workspaceRoot, "inside-link.py");
  await mkdir(workspaceRoot);
  await writeFile(insideFile, "print('inside')\n");
  await writeFile(outsideFile, "print('outside')\n");
  await symlink(outsideFile, outsideLink, "file");
  await symlink(insideFile, insideLink, "file");

  try {
    assert.equal(await isContainedRegularFile(workspaceRoot, insideFile), true);
    assert.equal(await isContainedRegularFile(workspaceRoot, insideLink), true);
    assert.equal(await isContainedRegularFile(workspaceRoot, outsideFile), false);
    assert.equal(await isContainedRegularFile(workspaceRoot, outsideLink), false);
    assert.equal(await isContainedRegularFile(workspaceRoot, workspaceRoot), false);
    assert.equal(await isContainedRegularFile(workspaceRoot, "missing.py"), false);

    const safePaths = await containedRegularFiles(workspaceRoot, [
      insideFile,
      outsideLink,
      insideLink,
    ]);
    assert.deepEqual(safePaths, [insideFile, insideLink]);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});
