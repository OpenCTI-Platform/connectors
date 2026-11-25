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
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "accesskey",
    "access-key",
    "private_key",
    "privatekey",
    "credit_card",
    "card_number",
    "cvv",
)
# Values found under sensitive keys are also masked wherever else they appear.
# Below _MIN_SUBSTRING_SECRET_LENGTH only whole-word matches are masked, so a
# short password does not mask parts of unrelated words.
_MIN_KNOWN_SECRET_LENGTH = 3
_MIN_SUBSTRING_SECRET_LENGTH = 6

# A quoted value, with escaped quotes inside: "a b\"c" or 'a b'.
_QUOTED = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'"
# "Password: x", "pass=x", "DB_PASSWORD=x", "api_key: x", and quoted
# assignments in leaked source code: {"password": "x y"}, api_key = 'x'.
_LABELED_SECRET = re.compile(
    r"(?i)(?<![a-z0-9])(pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?key)"
    r"(['\"]?\s*[:=]\s*)(" + _QUOTED + r"|\S+)"
)
# Header-style values span spaces and semicolons: "Cookie: a=1; b=2",
# "Authorization: Bearer x". Unless quoted, the rest of the line is masked.
_HEADER_SECRET = re.compile(
    r"(?i)\b(cookie|set-cookie|authorization)(['\"]?\s*[:=]\s*)("
    + _QUOTED
    + r"|[^\r\n]+)"
)
# "user@example.com:secret", including all-digit passwords.
_EMAIL_SECRET = re.compile(r"([\w.+-]+@[\w-]+(?:\.[\w-]+)+):(\S+)")
_PORT = re.compile(r"\d+\b")


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
    text = _HEADER_SECRET.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{_mask_value_text(m.group(3).strip())}",
        text,
    )
    text = _LABELED_SECRET.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{_mask_value_text(m.group(3))}", text
    )
    text = _EMAIL_SECRET.sub(_mask_email_secret, text)
    for secret in known_secrets:
        if secret not in text:
            continue
        if len(secret) >= _MIN_SUBSTRING_SECRET_LENGTH:
            text = text.replace(secret, mask_secret(secret))
        else:
            text = re.sub(
                rf"(?<!\w){re.escape(secret)}(?!\w)", mask_secret(secret), text
            )
    return text


def _mask_value_text(value: str) -> str:
    """Mask a matched value, keeping the quotes around a quoted one."""
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        inner = value[1:-1]
        return f"{value[0]}{mask_secret(inner)}{value[0]}" if inner else value
    return mask_secret(value)


def _mask_email_secret(match: re.Match) -> str:
    # In scheme://user@host:8443 the digits are a port, not a password.
    before = match.string[: match.start()]
    if before.endswith("://") and _PORT.match(match.group(2)):
        return match.group(0)
    return f"{match.group(1)}:{mask_secret(match.group(2))}"


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
