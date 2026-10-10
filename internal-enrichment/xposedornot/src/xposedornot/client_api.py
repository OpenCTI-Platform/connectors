"""Client for the XposedOrNot data-breach API.

Community API (no key): GET <base_url>/v1/breach-analytics?email=<email>
Plus API (key set):     GET https://plus-api.xposedornot.com/v3/check-email/<email>?detailed=true

Both responses are normalised to
    {"breaches": [<breach>, ...], "risk_label": str | None, "risk_score": Any}
A clean address (no known breach) is {}. Every failure raises XposedOrNotError.
"""

from __future__ import annotations

import html
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, NoReturn
from urllib.parse import quote, unquote

import requests
from src.xposedornot.errors import XposedOrNotError

FREE_BASE_URL = "https://api.xposedornot.com"
PLUS_BASE_URL = "https://plus-api.xposedornot.com"
USER_AGENT = "opencti-xposedornot-connector/1.0 (+https://github.com/XposedOrNot)"
DEFAULT_RETRY_AFTER = 15
MIN_RETRY_AFTER = 1
MAX_RETRY_AFTER = 60
MAX_RETRIES = 3
MAX_DECODE_PASSES = 20
MAX_LOGGED_CHARS = 300


def retry_after_seconds(value: Any, default: int = DEFAULT_RETRY_AFTER) -> int:
    """Seconds to wait from a Retry-After header, delta-seconds or HTTP-date."""
    text = str(value or "").strip()
    if not text:
        return default
    if text.isascii() and text.isdigit():
        return int(text)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return default
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, math.ceil((when - datetime.now(timezone.utc)).total_seconds()))


def redact(text: str, *secrets: str | None) -> str:
    """Blank every secret, raw or percent-encoded, without regard to case.

    Matches are located in the original text and blanked in one pass, so
    overlapping secrets cannot expose each other. If a secret is still legible
    once the result is fully decoded, the whole text is dropped.
    """
    known = [secret for secret in secrets if secret]
    if not text or not known:
        return text
    forms = dict.fromkeys(f for s in known for f in (quote(s, safe=""), s))
    spans: list[list[int]] = []
    for start, end in sorted(
        m.span() for f in forms for m in re.finditer(re.escape(f), text, re.I)
    ):
        if spans and start <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([start, end])
    pieces, cursor = [], 0
    for start, end in spans:
        pieces += [text[cursor:start], "<redacted>"]
        cursor = end
    redacted = "".join(pieces) + text[cursor:]
    decoded = redacted
    for _ in range(MAX_DECODE_PASSES):
        step = html.unescape(unquote(decoded))
        if step == decoded:
            break
        decoded = step
    else:
        return "<redacted>"
    if any(s.casefold() in decoded.casefold() for s in known):
        return "<redacted>"
    return redacted


def usable_score(value: Any) -> int | None:
    """The risk score as an integer in 0-100, or None when it is not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    return int(value) if 0 <= value <= 100 else None


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _scalar(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool)) else None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _data_classes(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else str(value or "").split(";")
    return [str(i).strip() for i in items if i is not None and str(i).strip()]


def _breach(entry: Any, name_key: str, date_key: str) -> dict[str, Any] | None:
    entry = _as_dict(entry)
    name = _text(entry.get(name_key))
    if name is None:
        return None
    return {
        "name": name,
        "date": _scalar(entry.get(date_key)),
        "records": _to_int(entry.get("xposed_records")),
        "domain": _scalar(entry.get("domain")),
        "industry": _scalar(entry.get("industry")),
        "password_risk": _scalar(entry.get("password_risk")),
        "verified": _scalar(entry.get("verified")),
        "data_classes": _data_classes(entry.get("xposed_data")),
        "details": _text(entry.get("details")),
    }


def _normalise_free(data: dict[str, Any]) -> dict[str, Any]:
    entries = _as_list(_as_dict(data.get("ExposedBreaches")).get("breaches_details"))
    breaches = [b for e in entries if (b := _breach(e, "breach", "xposed_date"))]
    if not breaches:
        return {}
    risk = _as_list(_as_dict(data.get("BreachMetrics")).get("risk"))
    first = _as_dict(risk[0]) if risk else {}
    return {
        "breaches": breaches,
        "risk_label": _scalar(first.get("risk_label")),
        "risk_score": first.get("risk_score"),
    }


def _normalise_plus(data: dict[str, Any]) -> dict[str, Any]:
    entries = _as_list(data.get("breaches"))
    breaches = [b for e in entries if (b := _breach(e, "breach_id", "breached_date"))]
    if not breaches:
        return {}
    return {"breaches": breaches, "risk_label": None, "risk_score": None}


class XposedOrNotClient:
    def __init__(
        self,
        helper: Any,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.helper = helper
        self.api_key = (api_key or "").strip() or None
        self.base_url = (base_url or FREE_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": USER_AGENT}
        )
        if self.api_key:
            self.session.headers["x-api-key"] = self.api_key

    def _fail(self, message: str, email: str, **meta: Any) -> NoReturn:
        safe = {
            key: redact(str(value), email, self.api_key)[:MAX_LOGGED_CHARS]
            for key, value in meta.items()
        }
        self.helper.connector_logger.error(message, meta=safe)
        raise XposedOrNotError(message) from None

    def lookup(self, email: str) -> dict[str, Any]:
        """Normalised breach exposure of an address, {} when it is clean."""
        if self.api_key:
            url = f"{PLUS_BASE_URL}/v3/check-email/{quote(email, safe='')}"
            params = {"detailed": "true"}
        else:
            url = f"{self.base_url}/v1/breach-analytics"
            params = {"email": email}

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.get(
                    url, params=params, timeout=self.timeout, allow_redirects=False
                )
            except requests.RequestException as exc:
                self._fail(
                    "XposedOrNot request failed",
                    email,
                    error=type(exc).__name__,
                    detail=str(exc),
                )
            if resp.status_code == 404:
                return {}
            if resp.status_code == 429:
                self.helper.connector_logger.warning(
                    "XposedOrNot rate limited; backing off",
                    meta={"attempt": attempt, "keyless": self.api_key is None},
                )
                if attempt < MAX_RETRIES:
                    wait = retry_after_seconds(resp.headers.get("Retry-After"))
                    time.sleep(min(max(wait, MIN_RETRY_AFTER), MAX_RETRY_AFTER))
                continue
            if 300 <= resp.status_code < 400:
                self._fail(
                    "XposedOrNot: redirect refused",
                    email,
                    status=resp.status_code,
                    location=resp.headers.get("Location", ""),
                )
            if resp.status_code in (401, 403, 422):
                self._fail(
                    "XposedOrNot: request rejected"
                    + (" (check the API key)" if self.api_key else ""),
                    email,
                    status=resp.status_code,
                )
            if resp.status_code >= 400:
                self._fail(
                    "XposedOrNot: error response",
                    email,
                    status=resp.status_code,
                    body=resp.text,
                )
            try:
                data = resp.json()
            except ValueError:
                self._fail("XposedOrNot: invalid JSON in response", email)
            if not isinstance(data, dict):
                self._fail(
                    "XposedOrNot: unexpected JSON payload",
                    email,
                    type=type(data).__name__,
                )
            return _normalise_plus(data) if self.api_key else _normalise_free(data)

        self._fail("XposedOrNot: still rate limited after retries", email)
