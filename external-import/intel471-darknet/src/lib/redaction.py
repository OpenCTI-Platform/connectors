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


def redact_url_in_text(text, url) -> str:
    """Return ``text`` with every occurrence of ``url`` replaced by its redacted form.

    The connector's HTTP-failure warnings include both the URL we
    were trying to fetch and the underlying ``requests`` exception
    message. ``requests`` formats most exceptions as
    ``"... for url: <full-url>"`` so the original full URL ends up
    in the exception text — including any signed query parameters
    on third-party CDN downloads. ``redact_url_in_text`` sanitises
    the exception text by substituting the known full URL with the
    output of :func:`redact_url` so the warning still surfaces the
    underlying error (HTTP status, connection-error class, …)
    without leaking the signed query string back into the logs.

    Defensive: accepts arbitrary input for both arguments and never
    raises (a failing substitution returns ``str(text)`` so the
    caller's log call still produces something printable).
    """
    if not text:
        return ""
    try:
        text_str = text if isinstance(text, str) else str(text)
    except Exception:  # noqa: BLE001
        return ""
    if not url:
        return text_str
    try:
        url_str = url if isinstance(url, str) else str(url)
    except Exception:  # noqa: BLE001
        return text_str
    if not url_str or url_str not in text_str:
        return text_str
    return text_str.replace(url_str, redact_url(url_str))


__all__ = ("redact_url", "redact_url_in_text")
