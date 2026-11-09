"""Mask credentials in a Vision alert before it is mapped to STIX.

Vision delivers leaked passwords, cookies and tokens both under named keys
(``password``) and inside free text (``url:Password: …`` combo lines,
``email:password`` pairs in chat messages). Anything that reaches STIX is
shared with every OpenCTI user allowed to see the marking, every stream
consumer and every export, so secrets are masked here, once, for all mappers.
The mask keeps enough to tell whether a password is still the current one;
the full value stays one click away in Vision via the alert's deep link.
"""

from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credit_card",
    "card_number",
    "cvv",
)
# Shorter values found under sensitive keys are masked in place but not
# searched for elsewhere, to avoid masking unrelated words.
_MIN_KNOWN_SECRET_LENGTH = 6

# "Password: x", "pass=x", "pwd: x"
_LABELED_SECRET = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd)(\s*[:=]\s*)(\S+)")
# "user@example.com:secret". A numeric suffix is a port, not a password.
_EMAIL_SECRET = re.compile(r"([\w.+-]+@[\w-]+(?:\.[\w-]+)+):(?!\d+\b)(\S+)")


def mask_secret(value: str) -> str:
    """Keep the first and last two characters and the length."""
    if len(value) < 8:
        return f"*** ({len(value)} chars)"
    return f"{value[:2]}***{value[-2:]} ({len(value)} chars)"


def redact_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the alert with every credential masked."""
    secrets: set[str] = set()
    _collect_secrets(alert, secrets, sensitive=False)
    return _scrub(alert, sorted(secrets, key=len, reverse=True))


def scrub_text(text: str, known_secrets: list[str]) -> str:
    """Mask credentials that appear inside a free-text value."""
    text = _LABELED_SECRET.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{mask_secret(m.group(3))}", text
    )
    text = _EMAIL_SECRET.sub(lambda m: f"{m.group(1)}:{mask_secret(m.group(2))}", text)
    for secret in known_secrets:
        if secret in text:
            text = text.replace(secret, mask_secret(secret))
    return text


def _is_sensitive_key(key: Any) -> bool:
    lowered = str(key).lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _collect_secrets(value: Any, secrets: set[str], sensitive: bool) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            _collect_secrets(inner, secrets, sensitive or _is_sensitive_key(key))
    elif isinstance(value, list):
        for item in value:
            _collect_secrets(item, secrets, sensitive)
    elif sensitive and isinstance(value, str):
        text = value.strip()
        if len(text) >= _MIN_KNOWN_SECRET_LENGTH:
            secrets.add(text)


def _scrub(value: Any, known_secrets: list[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                _mask_value(inner)
                if _is_sensitive_key(key)
                else _scrub(inner, known_secrets)
            )
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item, known_secrets) for item in value]
    if isinstance(value, str):
        return scrub_text(value, known_secrets)
    return value


def _mask_value(value: Any) -> Any:
    # Empty values stay as they are so the Note still shows the key existed.
    if value is None or value == "":
        return value
    if isinstance(value, str):
        return mask_secret(value)
    return "[redacted]"
