"""Secret masking for findings and reports.

A detected secret must never appear verbatim in any output — the JSON
report is committed to logs and the markdown report is pasted into agent
context windows. The mask keeps just enough signal to locate and correlate
the secret (prefix + stable hash handle + length) without revealing it.
"""

from __future__ import annotations

import hashlib


def mask_secret(value: str) -> str:
    """Return a redacted stand-in for a secret value."""
    if not value:
        return ""
    handle = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{value[:4]}…{handle} ({len(value)} chars)"
