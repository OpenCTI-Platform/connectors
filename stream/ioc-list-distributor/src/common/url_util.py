"""URL helpers used by the exporter (host for the exclude lists, scheme stripping)."""

from __future__ import annotations

from urllib.parse import urlsplit


def url_without_scheme(url: str) -> str:
    """The URL without its 'scheme://' prefix."""
    return url.split("://", 1)[1] if "://" in url else url


def url_host(url: str) -> str | None:
    """The host part of a URL, or None."""
    try:
        return urlsplit(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
