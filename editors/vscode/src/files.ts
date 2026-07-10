import { realpath, stat } from "node:fs/promises";
import * as path from "node:path";

export async function containedRegularFiles(
  workspaceRoot: string,
  candidatePaths: string[],
): Promise<string[]> {
  const canonicalRoot = await canonicalDirectory(workspaceRoot);
  const containedPaths: string[] = [];
  for (const candidatePath of candidatePaths) {
    const canonicalFile = await canonicalRegularFile(candidatePath);
    if (canonicalFile !== undefined && pathIsInside(canonicalRoot, canonicalFile)) {
      containedPaths.push(candidatePath);
    }
  }
  return containedPaths;
}

export async function isContainedRegularFile(
  workspaceRoot: string,
  filePath: string,
): Promise<boolean> {
  try {
    const canonicalRoot = await canonicalDirectory(workspaceRoot);
    const canonicalFile = await canonicalRegularFile(filePath);
    return canonicalFile !== undefined && pathIsInside(canonicalRoot, canonicalFile);
  } catch {
    return false;
  }
}

async function canonicalDirectory(directoryPath: string): Promise<string> {
  const canonicalPath = await realpath(directoryPath);
  const metadata = await stat(canonicalPath);
  if (!metadata.isDirectory()) {
    throw new Error("Workspace root is not a directory.");
  }
  return canonicalPath;
}

async function canonicalRegularFile(filePath: string): Promise<string | undefined> {
  try {
    const canonicalPath = await realpath(filePath);
    const metadata = await stat(canonicalPath);
    return metadata.isFile() ? canonicalPath : undefined;
  } catch {
    return undefined;
  }
}

function pathIsInside(root: string, candidate: string): boolean {
  const relativePath = path.relative(root, candidate);
  if (relativePath.length === 0 || relativePath === "..") {
    return false;
  }
  return !relativePath.startsWith(`..${path.sep}`) && !path.isAbsolute(relativePath);
}
