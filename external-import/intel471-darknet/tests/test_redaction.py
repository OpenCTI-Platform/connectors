"""Unit tests for :func:`lib.redaction.redact_url`.

The connector logs HTTP-failure warnings that include the failing URL
so operators can diagnose download problems. Some of those URLs are
**not** Intel 471 endpoints — the API returns ``imageOriginal`` /
attachment links that point at third-party CDNs and may carry signed
query parameters (e.g. AWS-style ``X-Amz-Signature``) or other
bearer-style tokens. The pinned invariants below make sure those
short-lived credentials never reach the connector logs:

* the host and path are always preserved (so operators can identify
  which resource failed);
* the query string and fragment are always replaced by
  ``<redacted>`` markers when present (so signed query parameters /
  bearer tokens are never logged verbatim);
* the helper is defensive — ``None`` / empty / non-string / unparseable
  inputs do **not** raise, so a logging call never masks the
  underlying network error the caller is trying to surface.
"""

import pytest
from lib.redaction import redact_url


class TestQueryAndFragmentRedaction:
    """Query / fragment parts are replaced by ``<redacted>`` markers."""

    def test_query_with_signed_parameters_is_redacted(self):
        url = (
            "https://cdn.example.org/img.png"
            "?X-Amz-Signature=abcdef&X-Amz-Expires=900"
        )
        result = redact_url(url)
        assert result == "https://cdn.example.org/img.png?<redacted>"
        # Defence in depth: the signature must not appear anywhere in
        # the redacted output, even partially.
        assert "abcdef" not in result
        assert "X-Amz-Signature" not in result
        assert "X-Amz-Expires" not in result

    def test_query_with_bearer_token_is_redacted(self):
        url = "https://example.org/api?token=Bearer_secret_value"
        result = redact_url(url)
        assert result == "https://example.org/api?<redacted>"
        assert "secret_value" not in result

    def test_fragment_is_redacted(self):
        url = "https://example.org/page#secret-section"
        result = redact_url(url)
        assert result == "https://example.org/page#<redacted>"
        assert "secret-section" not in result

    def test_query_and_fragment_are_both_redacted(self):
        url = "https://example.org/path?token=abc#section"
        result = redact_url(url)
        assert result == "https://example.org/path?<redacted>#<redacted>"
        assert "abc" not in result
        assert "section" not in result


class TestHostAndPathPreservation:
    """Host and path stay intact so operators can identify the resource."""

    def test_intel471_url_without_query_is_unchanged(self):
        url = "https://api.intel471.com/alerts/123"
        assert redact_url(url) == url

    def test_path_is_preserved_with_redacted_query(self):
        url = "https://cdn.example.org/path/to/img.png?signed=1"
        assert redact_url(url) == "https://cdn.example.org/path/to/img.png?<redacted>"

    def test_port_is_preserved(self):
        url = "https://api.intel471.com:8443/alerts"
        assert redact_url(url) == url

    def test_path_only_url_is_preserved(self):
        # Some callers may pass a relative path; we still want a
        # sensible output that does not leak the query string.
        url = "/alerts/123?from=foo"
        assert redact_url(url) == "/alerts/123?<redacted>"


class TestDefensiveBehaviour:
    """The helper must never raise from a logging path."""

    @pytest.mark.parametrize("blank", [None, "", 0, False])
    def test_blank_input_returns_empty_marker(self, blank):
        assert redact_url(blank) == "<empty url>"

    def test_non_string_input_is_coerced(self):
        # ``urlparse`` accepts ``str``; the helper must coerce
        # arbitrary types via ``str(...)`` rather than raising.
        class _U:
            def __str__(self) -> str:
                return "https://example.org/resource?secret=1"

        assert redact_url(_U()) == "https://example.org/resource?<redacted>"

    def test_unparseable_input_does_not_raise(self):
        # ``urlparse`` is surprisingly forgiving — most "garbage" inputs
        # parse as path-only URLs. The helper must still return a
        # printable string for every input.
        result = redact_url("not a url at all")
        assert isinstance(result, str)
        assert "secret" not in result


class TestNoCredentialLeak:
    """End-to-end: no input substring containing the redacted query / fragment leaks out."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://s3.amazonaws.com/intel471/img.png?X-Amz-Signature=DEADBEEF",
            "https://cdn.example.org/file?token=DEADBEEF",
            "https://example.org/path?api_key=DEADBEEF",
            "https://example.org/path#DEADBEEF",
        ],
    )
    def test_signed_query_value_never_appears_in_output(self, url):
        assert "DEADBEEF" not in redact_url(url)
