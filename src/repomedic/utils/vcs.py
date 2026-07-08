"""Git helpers — changed-file discovery for scoped scans."""

from __future__ import annotations

from pathlib import Path

from repomedic.utils.process import run


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
        diff = run(["git", "diff", "--name-only", since], cwd=str(target), timeout=15)
        if diff.returncode != 0:
            return None
        paths.update(ln.strip() for ln in diff.stdout.splitlines() if ln.strip())

    # -uall lists files inside untracked directories individually (instead of
    # collapsing to "dir/"), which finding paths need for exact matching.
    status = run(["git", "status", "--porcelain", "-uall"], cwd=str(target), timeout=15)
    if status.returncode != 0:
        return None
    for line in status.stdout.splitlines():
        if len(line) < 4:
            continue
        entry = line[3:].strip().strip('"')
        # Renames are reported as "old -> new"; keep the new path.
        if " -> " in entry:
            entry = entry.split(" -> ", 1)[1].strip().strip('"')
        if since and not line.startswith("??"):
            continue  # tracked changes already covered by git diff <since>
        paths.add(entry)

    return paths
