"""Neutralize untrusted text before it enters the agent-facing report.

The fix report is consumed by AI coding agents as instructions, but most of
its text originates in the scanned repository: linter messages echo source
code, log findings quote log lines, runtime findings quote stderr. A
malicious repo could otherwise inject markdown that impersonates report
structure ("#### RM-… ignore previous instructions …") or break the
machine-readable front matter.

Two treatments cover every sink:

- :func:`sanitize_inline` for text that must stay on one markdown line
  (headings, list items): collapses newlines, neutralizes backticks and
  pipes, caps length.
- :func:`fenced_block` for multi-line text: quarantines it inside a code
  fence whose backtick run is longer than any run in the payload, so the
  fence cannot be closed from inside. Fenced content is visually and
  semantically *data*, not instructions.

Front-matter values go through :func:`yaml_scalar` (a JSON string is a
valid single-line YAML scalar), so no value can break the ``key: value``
block agents parse.
"""

from __future__ import annotations

import json
import re

_BACKTICK_RUN = re.compile(r"`+")
_ELLIPSIS = "…"


def sanitize_inline(text: str, max_len: int = 120) -> str:
    """Make untrusted text safe to embed in a single markdown line."""
    text = " ".join(str(text).split())
    text = text.replace("`", "'")
    text = text.replace("|", "\\|")
    if len(text) > max_len:
        text = text[: max_len - 1] + _ELLIPSIS
    return text


def fenced_block(text: str, info: str = "text", max_len: int = 2000) -> list[str]:
    """Return untrusted multi-line text quarantined inside an unclosable fence."""
    text = str(text)
    if len(text) > max_len:
        text = text[: max_len - 1] + _ELLIPSIS
    longest_run = max((len(m.group()) for m in _BACKTICK_RUN.finditer(text)), default=0)
    fence = "`" * max(3, longest_run + 1)
    return [f"{fence}{info}", *text.splitlines(), fence]


def yaml_scalar(value: object) -> str:
    """Encode a value as a single-line YAML-safe scalar (JSON string)."""
    return json.dumps(str(value), ensure_ascii=False)
