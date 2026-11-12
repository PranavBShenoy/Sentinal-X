"""
Secret Redactor — strips secrets from strings before logging or storing.

Patterns are intentionally broad to minimize false negatives.
False positives (redacting non-secret data) are acceptable;
failing to redact a real secret is not.
"""
from __future__ import annotations

import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Compiled patterns — (name, regex)
# ---------------------------------------------------------------------------

_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Generic high-entropy strings that look like tokens/keys
    ("aws_access_key", re.compile(r"(?i)(AKIA[0-9A-Z]{16})")),
    ("aws_secret_key", re.compile(r"(?i)(aws.{0,20}secret.{0,20}['\"]?)([0-9a-zA-Z/+]{40})")),
    # GitHub tokens
    ("github_token", re.compile(r"(?i)(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})")),
    # Slack tokens
    ("slack_token", re.compile(r"xox[baprs]-[0-9a-zA-Z\-]+")),
    # Stripe
    ("stripe_key", re.compile(r"(?i)(sk_live_[a-zA-Z0-9]{24,}|pk_live_[a-zA-Z0-9]{24,})")),
    # Generic API key patterns
    ("api_key_assignment", re.compile(
        r"(?i)(api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)"
        r"[^\S\r\n]*[=:][^\S\r\n]*"
        r"(['\"]?)([a-zA-Z0-9_\-\.]{16,})\2"
    )),
    # Password assignment
    ("password_assignment", re.compile(
        r"(?i)(password|passwd|pwd|secret)[^\S\r\n]*[=:][^\S\r\n]*"
        r"(['\"]?)([^\s'\"]{8,})\2"
    )),
    # Private key blocks
    ("private_key_block", re.compile(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        re.MULTILINE,
    )),
    # Bearer tokens in HTTP headers
    ("bearer_header", re.compile(r"(?i)Authorization:\s*Bearer\s+([a-zA-Z0-9_\-\.=]+)")),
    # Connection strings with embedded credentials
    ("connection_string", re.compile(
        r"(?i)(postgresql|mysql|mongodb|redis|amqp)://([^:@\s]+):([^@\s]+)@"
    )),
    # Generic high-entropy hex strings (40+ hex chars — SHA tokens, secrets)
    ("hex_secret", re.compile(r"(?<![a-f0-9])([a-f0-9]{40,64})(?![a-f0-9])")),
    # Base64-looking secrets in common patterns
    ("base64_secret", re.compile(
        r"(?i)(secret|token|key|credential)[^\S\r\n]*[=:][^\S\r\n]*"
        r"([a-zA-Z0-9+/]{20,}={0,2})"
    )),
]


def redact(text: str, replacement: str = "[REDACTED]") -> str:
    """
    Return *text* with all detected secret patterns replaced by *replacement*.

    This is a best-effort heuristic. Never rely solely on this function for
    security — the right approach is to never have secrets in strings at all.
    """
    if not text:
        return text

    result = text
    for _name, pattern in _PATTERNS:
        try:
            result = pattern.sub(replacement, result)
        except Exception:
            # Never let a buggy pattern crash the application
            pass
    return result


def redact_dict(obj: object, replacement: str = "[REDACTED]") -> object:
    """
    Recursively walk a dict/list structure, redacting secrets from string values.
    Returns a new object (does not mutate the input).
    """
    if isinstance(obj, str):
        return redact(obj, replacement)
    if isinstance(obj, dict):
        return {k: redact_dict(v, replacement) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_dict(item, replacement) for item in obj]
    return obj


def mask_secret(value: str, keep_prefix: int = 4, keep_suffix: int = 2, max_len: int = 10) -> str:
    """
    Mask a known secret value for safe storage/display.
    Returns first *keep_prefix* chars + "..." + last *keep_suffix* chars,
    capped to *max_len* visible characters total.

    Example: mask_secret("ghp_ABCDEF1234567890XYZ") -> "ghp_...YZ"
    """
    if not value:
        return "[EMPTY]"
    if len(value) <= keep_prefix + keep_suffix:
        return "[REDACTED]"

    prefix = value[:keep_prefix]
    suffix = value[-keep_suffix:] if keep_suffix > 0 else ""
    masked = f"{prefix}...{suffix}"
    if len(masked) > max_len:
        masked = masked[:max_len]
    return masked
