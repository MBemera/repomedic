"""Guard: docs/AGENTS.md is a byte-equal copy of the packaged canonical guide.

The canonical agents guide ships inside the package (printed by
`repomedic agents`); the repo copy exists for browsing on GitHub. If this
test fails, regenerate the copy:

    repomedic agents > docs/AGENTS.md
"""

from __future__ import annotations

from pathlib import Path

from repomedic.commands.agents import get_agent_guide

REPO_ROOT = Path(__file__).parent.parent


def test_docs_agents_md_matches_packaged_guide():
    docs_copy = REPO_ROOT / "docs" / "AGENTS.md"
    assert docs_copy.is_file(), "docs/AGENTS.md is missing — run: repomedic agents > docs/AGENTS.md"
    assert docs_copy.read_bytes() == get_agent_guide().encode("utf-8"), (
        "docs/AGENTS.md has drifted from src/repomedic/data/AGENTS.md — "
        "regenerate it with: repomedic agents > docs/AGENTS.md"
    )
