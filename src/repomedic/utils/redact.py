"""Secret masking for findings and reports.

A detected secret must never appear verbatim in any output — the JSON
report is committed to logs and the markdown report is pasted into agent
context windows. The mask keeps just enough signal to locate and correlate
the secret (prefix + stable hash handle + length) without revealing it.
"""

from __future__ import annotations

import hashlib
import re


_SENSITIVE_VARIABLE_NAME = re.compile(
    r"(?:^|_)(?:api_?key|access_?key|auth|cookie|credential|env|environ|"
    r"pass(?:word|wd)?|private_?key|secret|session|token)(?:$|_)",
    re.IGNORECASE,
)

_SECRET_TEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})\b"),
    re.compile(
        r"(?i)(?:password|passwd|api_?key|secret|token)['\"]?\s*[=:]\s*"
        r"['\"]?([^'\"\s,}]{8,})"
    ),
)


def mask_secret(value: str) -> str:
    """Return a redacted stand-in for a secret value."""
    if not value:
        return ""
    handle = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{value[:4]}…{handle} ({len(value)} chars)"


def redact_sensitive_text(text: str) -> str:
    """Mask common credential shapes found in captured output or values."""
    redacted = text
    for pattern in _SECRET_TEXT_PATTERNS:
        redacted = pattern.sub(_replace_secret_match, redacted)
    return redacted


def redact_debug_variable(name: str, value: str) -> str:
    """Redact a debugger value based on its name and credential shapes."""
    if _SENSITIVE_VARIABLE_NAME.search(name):
        return "[REDACTED]"
    return redact_sensitive_text(value)


def _replace_secret_match(match: re.Match[str]) -> str:
    secret = match.group(1)
    return match.group(0).replace(secret, mask_secret(secret))
