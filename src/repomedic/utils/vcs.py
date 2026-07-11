"""Git helpers — hardened git invocation and changed-file discovery."""

from __future__ import annotations

from pathlib import Path

from repomedic.utils.process import ProcessResult, run

# A scanned repo's own .git/config must not be able to execute code when we
# inspect it: core.fsmonitor can name a command `git status` would run, and
# hooksPath could point hooks at repo-controlled scripts.
_GIT_HARDENING = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath="]


def run_git(args: list[str], *, cwd: str, timeout: int = 15) -> ProcessResult:
    """Run a git command against a possibly untrusted repository."""
    return run(["git", *_GIT_HARDENING, *args], cwd=cwd, timeout=timeout)


def changed_files(target: Path, since: str | None = None) -> set[str] | None:
    """Return repo-relative paths of changed files, or None if git is unusable.

    Without ``since``: staged + unstaged + untracked files (``git status``).
    With ``since``: files that differ from that ref (``git diff <since>``),
    plus untracked files.
    """
    if not (target / ".git").is_dir():
        return None

    paths: set[str] = set()

    if since:
        diff = run_git(["diff", "--name-only", "-z", since], cwd=str(target))
        if not diff.ok:
            return None
        paths.update(p for p in diff.stdout.split("\0") if p)

    # -z gives NUL-separated, unquoted paths (spaces/unicode survive intact);
    # -uall lists files inside untracked directories individually (instead of
    # collapsing to "dir/"), which finding paths need for exact matching.
    status = run_git(["status", "--porcelain", "-z", "-uall"], cwd=str(target))
    if not status.ok:
        return None

    fields = status.stdout.split("\0")
    i = 0
    while i < len(fields):
        entry = fields[i]
        i += 1
        if len(entry) < 4:
            continue
        xy, path = entry[:2], entry[3:]
        # Renames/copies are "XY new" followed by the original path as its
        # own NUL field — consume it so it is not parsed as an entry.
        if xy[0] in "RC":
            i += 1
        if since and not xy.startswith("??"):
            continue  # tracked changes already covered by git diff <since>
        paths.add(path)

    return paths
