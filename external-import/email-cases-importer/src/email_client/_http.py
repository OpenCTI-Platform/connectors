"""Shared HTTP robustness helpers for the REST-based email clients.

Centralizes two behaviors the OpenCTI maintainers require (see
OpenCTI-Platform/connectors#6164):

* `parse_json` — tolerate a non-JSON 200 body (e.g. an HTML error page from a
  proxy/WAF) by raising a clear, typed error with a short body preview, instead
  of surfacing an opaque ``ValueError`` deep inside response parsing.
* `get_with_retry` — honor HTTP 429 ``Retry-After`` with bounded backoff so a
  transient rate-limit doesn't fail the entire fetch cycle.

Used by the Microsoft Graph and Gmail clients (both built on requests).
"""

import time

_DEFAULT_RETRY_WAIT = 2
_MAX_RETRY_WAIT = 60


def _safe_int(value, default):
    """Best-effort int parse with a fallback (mirrors the #6164 helper)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class EmailClientHTTPError(RuntimeError):
    """Raised when an email REST API returns an unusable (non-JSON) response."""


def parse_json(resp):
    """Return ``resp.json()``, or raise EmailClientHTTPError on a non-JSON body.

    ``requests``' ``JSONDecodeError`` subclasses ``ValueError``, so a single
    except covers both stdlib and requests JSON failures.
    """
    try:
        return resp.json()
    except ValueError as exc:
        content_type = resp.headers.get("Content-Type", "unknown")
        preview = (resp.text or "")[:200]
        raise EmailClientHTTPError(
            f"Expected a JSON response but got Content-Type={content_type!r} "
            f"(HTTP {resp.status_code}): {preview!r}"
        ) from exc


def get_with_retry(session, url, *, max_retries=3, **kwargs):
    """``session.get`` that retries on HTTP 429, honoring ``Retry-After``.

    ``Retry-After`` is read as an integer number of seconds (the form Graph and
    Gmail use); a missing/non-integer value falls back to a safe default, and
    the wait is capped to avoid an unbounded stall.
    """
    resp = session.get(url, **kwargs)
    attempts = 0
    while resp.status_code == 429 and attempts < max_retries:
        wait = min(
            _safe_int(resp.headers.get("Retry-After"), _DEFAULT_RETRY_WAIT),
            _MAX_RETRY_WAIT,
        )
        time.sleep(max(wait, 0))
        resp = session.get(url, **kwargs)
        attempts += 1
    return resp
