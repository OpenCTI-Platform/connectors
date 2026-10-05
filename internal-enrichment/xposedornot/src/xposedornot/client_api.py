# -*- coding: utf-8 -*-
"""Client for the XposedOrNot data-breach API.

Community API (default, no key):
    GET https://api.xposedornot.com/v1/breach-analytics?email=<email>
Plus API (used automatically when an API key is configured):
    GET https://plus-api.xposedornot.com/v3/check-email/<email>?detailed=true
    Auth: header `x-api-key: <key>`

Both responses are normalised to a single shape:
    {"breaches": [<breach dict>, ...], "risk_label": str|None, "risk_score": Any}
`risk_score` is passed through as the API sent it; `usable_score` is the one
place that decides whether a value is publishable, so normalisation cannot
quietly turn a rejected value into an accepted one.
A clean result (email not found in any breach) is returned as {} — this is a
normal outcome, not an error. Errors return None (and are logged).
"""

from __future__ import annotations

import html
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote, unquote

import requests

FREE_BASE_URL = "https://api.xposedornot.com"
PLUS_BASE_URL = "https://plus-api.xposedornot.com"
USER_AGENT = "opencti-xposedornot-connector/1.0 (+https://github.com/XposedOrNot)"
DEFAULT_RETRY_AFTER = 15
MIN_RETRY_AFTER = 1
MAX_RETRY_AFTER = 60


def retry_after_seconds(value, default: int = DEFAULT_RETRY_AFTER) -> int:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date)."""
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
    remaining = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0, math.ceil(remaining))


MAX_DECODE_PASSES = 20


def decoded_layers(text: str) -> tuple[str, bool]:
    """Percent and HTML entity encoding peeled off, and whether that finished.

    A single `unquote` only removes one layer, so a value encoded twice still
    reads as encoded afterwards, and an HTML error page can spell the same
    address with character references instead. Each pass either shortens the text or leaves
    it alone, so this settles on its own; the cap only bounds the work done on
    something a third party sent, and sits far above any real encoding depth.

    Whether the cap was reached has to travel with the text. A payload encoded
    deeper than the cap stopped short of its plaintext, so the redaction check
    read an encoded string, found no secret in it, and returned a body a
    reader could still decode back to the address.
    """
    for _ in range(MAX_DECODE_PASSES):
        decoded = html.unescape(unquote(text))
        if decoded == text:
            return text, True
        text = decoded
    return text, False


def fully_decoded(text: str) -> str:
    """The text with as many layers of encoding removed as the cap allows."""
    return decoded_layers(text)[0]


def redact(text: str, *secrets: str | None) -> str:
    """Blank out every secret, in raw and URL-encoded form, before logging.

    Matched without regard to case. Percent-encoding is case-insensitive in its
    escape digits and `quote` only ever emits uppercase ones, so a server that
    answers with `user%2btag%40example.com` would slip a lowercase spelling of
    the address straight through a literal comparison and into the logs.

    Targeted replacement still only covers the spellings it knows, and any
    character may be percent-encoded, so the whole payload is dropped if the
    secret is still legible once the text is decoded, and also when the
    decoding never settled: text still encoded at the cap has not been shown
    to be clean, and a payload nobody can vouch for is not logged. Losing a
    diagnostic string is the cheaper mistake: what is being protected here is
    an address belonging to a person who did not choose to appear in these
    logs.

    Decoding repeats until it settles. One pass turns `%2573ecret` into
    `%73ecret` rather than into the secret, so a value encoded twice would
    have read as already clean and survived into the log.

    Every form is located in the original text and the spans are blanked
    together, because replacing one secret at a time let an earlier
    replacement destroy a later match: an API key that contained the address
    kept its prefix and suffix once the address inside it was blanked, and
    two secrets that merely overlapped left the tail of the second. Matching
    the untouched text makes the result independent of the order the caller
    passes them in.
    """
    if not text:
        return text
    forms = dict.fromkeys(
        form
        for secret in secrets
        if secret
        for form in (quote(secret, safe=""), secret)
    )
    spans = sorted(
        match.span()
        for form in forms
        for match in re.finditer(re.escape(form), text, flags=re.IGNORECASE)
    )
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces, cursor = [], 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append("<redacted>")
        cursor = end
    pieces.append(text[cursor:])
    redacted = "".join(pieces)
    if not forms:
        return redacted
    decoded, settled = decoded_layers(redacted)
    if not settled:
        return "<redacted>"
    if any(secret and secret.casefold() in decoded.casefold() for secret in secrets):
        return "<redacted>"
    return redacted


def _to_int(value):
    """The value as a whole number, or None when it is not one.

    Coercion must not invent a number the API did not send. `int()` turns
    True into 1 and 3.7 into 3, which would launder a value the score check
    downstream rejects outright into one it accepts, and it raises rather
    than returning on an infinity. A string spelling a whole number is still
    read, since that changes the notation and not the value.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def usable_score(value: Any) -> int | None:
    """The API's risk score as OpenCTI stores it, or None when it is unusable.

    `x_opencti_score` is an integer percentage. A string, a bool, a fraction
    or a value outside 0-100 is not one, and publishing whatever the API sent
    would either be rejected by the platform or stored as a number nobody can
    interpret. An unusable value is treated as no score at all rather than
    clamped, since a score this connector had to invent is worse than none.

    It lives here, beside the parsing, so the observable's score and the one
    written into the Note are decided by the same rule.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    score = int(value)
    return score if 0 <= score <= 100 else None


def _identifier(value: Any) -> str | None:
    """The name a breach record goes by, or None when it names nothing.

    A record with no identifier is not a breach this connector can report. It
    was being counted as one, so a response carrying an empty object produced
    "Found 1 breach(es)", labelled the observable `data-breach` and wrote a
    row of dashes into the note: an assertion that someone's address had been
    exposed, which the API never made.
    """
    return value.strip() if isinstance(value, str) and value.strip() else None


def _split_data_classes(value) -> list[str]:
    """The exposed data categories, from the `;`-joined string the API sends.

    A list is read as one entry per element. `str()` of a list would have
    produced a single category spelling out the list's own syntax.
    """
    items = value if isinstance(value, (list, tuple)) else str(value or "").split(";")
    return [
        str(item).strip() for item in items if item is not None and str(item).strip()
    ]


def _scalar(value: Any) -> Any:
    """A value fit to print as one field of the note, or None.

    The API documents these fields as strings. A list or a mapping in their
    place would be rendered as Python's spelling of the container and read by
    an analyst as the breach's domain or industry; nothing the API did not
    state as a single value is passed on.
    """
    return value if isinstance(value, (str, int, float, bool)) else None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalise_free(data: dict[str, Any]) -> dict[str, Any]:
    breaches = []
    exposed = _as_dict(data.get("ExposedBreaches"))
    for entry in _as_list(exposed.get("breaches_details")):
        if not isinstance(entry, dict):
            continue
        name = _identifier(entry.get("breach"))
        if name is None:
            continue
        breaches.append(
            {
                "name": name,
                "date": _scalar(entry.get("xposed_date")),
                "records": _to_int(entry.get("xposed_records")),
                "domain": _scalar(entry.get("domain")),
                "industry": _scalar(entry.get("industry")),
                "password_risk": _scalar(entry.get("password_risk")),
                "verified": _scalar(entry.get("verified")),
                "data_classes": _split_data_classes(entry.get("xposed_data")),
            }
        )
    if not breaches:
        return {}
    risk = _as_list(_as_dict(data.get("BreachMetrics")).get("risk"))
    first = _as_dict(risk[0]) if risk else {}
    risk_label = _scalar(first.get("risk_label"))
    risk_score = first.get("risk_score")
    return {"breaches": breaches, "risk_label": risk_label, "risk_score": risk_score}


def _normalise_plus(data: dict[str, Any]) -> dict[str, Any]:
    breaches = []
    for entry in _as_list(data.get("breaches")):
        if not isinstance(entry, dict):
            continue
        name = _identifier(entry.get("breach_id"))
        if name is None:
            continue
        breaches.append(
            {
                "name": name,
                "date": _scalar(entry.get("breached_date")),
                "records": _to_int(entry.get("xposed_records")),
                "domain": _scalar(entry.get("domain")),
                "industry": _scalar(entry.get("industry")),
                "password_risk": _scalar(entry.get("password_risk")),
                "verified": _scalar(entry.get("verified")),
                "data_classes": _split_data_classes(entry.get("xposed_data")),
            }
        )
    if not breaches:
        return {}
    return {"breaches": breaches, "risk_label": None, "risk_score": None}


class XposedOrNotClient:
    def __init__(
        self,
        helper,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: int = 30,
    ):
        self.helper = helper
        self.api_key = (api_key or "").strip() or None
        self.base_url = (base_url or FREE_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": USER_AGENT}
        )
        if self.api_key:
            self.session.headers.update({"x-api-key": self.api_key})

    def lookup(self, email: str) -> dict[str, Any] | None:
        """Look up breach exposure for an email.

        Returns the normalised result dict, {} for a clean email, or None on error.
        """
        if self.api_key:
            url = f"{PLUS_BASE_URL}/v3/check-email/{quote(email, safe='')}"
            params = {"detailed": "true"}
        else:
            url = f"{self.base_url}/v1/breach-analytics"
            params = {"email": email}

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                resp = self.session.get(
                    url, params=params, timeout=self.timeout, allow_redirects=False
                )
            except requests.RequestException as exc:
                self.helper.connector_logger.error(
                    "XposedOrNot request failed",
                    meta={
                        "error": type(exc).__name__,
                        "detail": redact(str(exc), email, self.api_key),
                    },
                )
                return None

            if resp.status_code == 404:
                # email not found in any breach -- normal, clean outcome
                return {}

            if 300 <= resp.status_code < 400:
                self.helper.connector_logger.error(
                    "XposedOrNot: redirect refused; the API must answer directly"
                    " over https",
                    meta={
                        "status": resp.status_code,
                        "location": redact(
                            resp.headers.get("Location", ""), email, self.api_key
                        ),
                    },
                )
                return None

            if resp.status_code == 429:
                if self.api_key:
                    message = "XposedOrNot Plus API rate limited; backing off."
                else:
                    message = (
                        "XposedOrNot rate limited (keyless: 2/s, 25/hour); backing"
                        " off. An optional API key raises limits."
                    )
                self.helper.connector_logger.warning(message, meta={"attempt": attempt})
                if attempt < max_retries:
                    wait = retry_after_seconds(resp.headers.get("Retry-After"))
                    time.sleep(min(max(wait, MIN_RETRY_AFTER), MAX_RETRY_AFTER))
                continue

            if resp.status_code in (401, 403, 422):
                if self.api_key:
                    message = "XposedOrNot: API key rejected by the Plus API"
                else:
                    message = "XposedOrNot: request rejected by the community API"
                self.helper.connector_logger.error(
                    message, meta={"status": resp.status_code}
                )
                return None
            if resp.status_code >= 400:
                self.helper.connector_logger.error(
                    "XposedOrNot: error response",
                    meta={
                        "status": resp.status_code,
                        "body": redact(resp.text, email, self.api_key)[:300],
                    },
                )
                return None

            try:
                data = resp.json()
            except ValueError:
                self.helper.connector_logger.error(
                    "XposedOrNot: invalid JSON in response."
                )
                return None
            if not isinstance(data, dict):
                self.helper.connector_logger.error(
                    "XposedOrNot: unexpected JSON payload type",
                    meta={"type": type(data).__name__},
                )
                return None

            return _normalise_plus(data) if self.api_key else _normalise_free(data)

        self.helper.connector_logger.error(
            "XposedOrNot: still rate limited after retries."
        )
        return None
