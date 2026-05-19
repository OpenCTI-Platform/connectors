"""URL-redaction helpers used by the Intel 471 connector.

This module is intentionally dependency-free (no ``pycti`` / ``stix2`` /
``requests``) so the redaction contract can be unit-tested on any CI
runner without the connector's full dependency chain being installed.

The connector logs HTTP-failure warnings that include the failing URL
so operators can diagnose download problems. Some of those URLs are
**not** Intel 471 endpoints — the API returns ``imageOriginal`` /
attachment links that point at third-party CDNs and may carry signed
query parameters (e.g. AWS-style ``X-Amz-Signature``) or other
bearer-style tokens. :func:`redact_url` strips the query and fragment
parts so the log line stays useful (host / path are preserved) without
leaking short-lived credentials into the connector logs.
"""

from urllib.parse import urlparse


def redact_url(url) -> str:
    """Return ``url`` with its query and fragment redacted.

    Accepts arbitrary input — ``None`` and non-string objects are
    handled defensively so a logging call never raises an exception
    that masks the underlying network error the caller is trying to
    surface. The return value is always a printable ``str``.

    Examples
    --------
    >>> redact_url("https://cdn.example.org/img.png?signature=abc&token=xyz")
    'https://cdn.example.org/img.png?<redacted>'
    >>> redact_url("https://api.intel471.com/alerts/123")
    'https://api.intel471.com/alerts/123'
    >>> redact_url(None)
    '<empty url>'
    """
    if not url:
        return "<empty url>"
    try:
        parsed = urlparse(str(url))
    except Exception:  # noqa: BLE001 - defensive: never fail a log call
        return "<unparseable url>"
    if parsed.scheme:
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        base = f"{parsed.netloc}{parsed.path}"
    if parsed.query:
        base += "?<redacted>"
    if parsed.fragment:
        base += "#<redacted>"
    return base or "<empty url>"


__all__ = ("redact_url",)
