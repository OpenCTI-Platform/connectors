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
from lib.redaction import redact_url, redact_url_in_text


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
            # Userinfo-bearing URLs (``user:password@host``) must not
            # leak through ``netloc``. The Intel 471 API returns
            # third-party CDN URLs whose shape is not under the
            # connector's control, so a hostile or accidentally
            # misconfigured upstream could send back a userinfo-bearing
            # ``imageOriginal`` URL — the helper must still scrub it.
            "https://USER:DEADBEEF@cdn.example.org/file?sig=xyz",
            "https://USER:DEADBEEF@cdn.example.org/file#frag",
            "https://USER:DEADBEEF@cdn.example.org/file",
        ],
    )
    def test_signed_query_value_never_appears_in_output(self, url):
        assert "DEADBEEF" not in redact_url(url)


class TestUserInfoStripping:
    """``username:password@`` userinfo is stripped from the redacted URL.

    ``urllib.parse.urlparse`` keeps userinfo in ``parsed.netloc``, so a
    naive ``f"{scheme}://{netloc}{path}"`` rebuild would still log
    ``token:secret@host``. The redaction helper rebuilds the authority
    from ``parsed.hostname`` and ``parsed.port`` so the userinfo never
    reaches the log line.
    """

    def test_userinfo_is_dropped_from_authority(self):
        url = "https://token:secret@cdn.example.org/file?sig=xyz"
        result = redact_url(url)
        assert result == "https://cdn.example.org/file?<redacted>"
        assert "token" not in result
        assert "secret" not in result
        assert "@" not in result

    def test_userinfo_is_dropped_when_no_query_or_fragment(self):
        url = "https://token:secret@cdn.example.org/file"
        result = redact_url(url)
        assert result == "https://cdn.example.org/file"
        assert "token" not in result
        assert "secret" not in result

    def test_userinfo_is_dropped_with_explicit_port(self):
        url = "https://token:secret@cdn.example.org:8443/file?sig=xyz"
        result = redact_url(url)
        assert result == "https://cdn.example.org:8443/file?<redacted>"
        assert "token" not in result
        assert "secret" not in result

    def test_password_only_userinfo_is_dropped(self):
        url = "https://secret@cdn.example.org/file"
        result = redact_url(url)
        assert result == "https://cdn.example.org/file"
        assert "secret" not in result

    def test_malformed_port_does_not_raise(self):
        # ``parsed.port`` raises ``ValueError`` when the port isn't a
        # valid integer; the helper must coerce that to ``None`` and
        # still emit a printable string instead of crashing the
        # logging call.
        result = redact_url("https://host:notaport/file?s=DEAD")
        assert isinstance(result, str)
        assert "DEAD" not in result


class TestRedactUrlInText:
    """``redact_url_in_text`` redacts URL substrings inside arbitrary text.

    ``requests.RequestException`` instances embed the original URL in
    their ``str()`` representation — ``"403 Client Error: Forbidden
    for url: <full-url>?signed=..."``. Logging ``str(exc)`` directly
    therefore leaks the signed query string even when the URL was
    redacted in the surrounding warning. ``redact_url_in_text`` is
    the helper that substitutes the known full URL with its redacted
    form inside an arbitrary text payload (typically an exception
    message) so the warning line cannot leak credentials through
    that secondary channel.
    """

    def test_replaces_full_url_with_redacted_form(self):
        url = "https://s3.amazonaws.com/img.png?X-Amz-Signature=DEADBEEF"
        text = (
            "403 Client Error: Forbidden for url: "
            "https://s3.amazonaws.com/img.png?X-Amz-Signature=DEADBEEF"
        )
        result = redact_url_in_text(text, url)
        assert "DEADBEEF" not in result
        assert "X-Amz-Signature" not in result
        assert "https://s3.amazonaws.com/img.png?<redacted>" in result
        # The HTTP-status prefix is preserved so operators can still
        # diagnose the failure.
        assert "403 Client Error" in result

    def test_replaces_every_occurrence(self):
        url = "https://example.org/p?t=DEAD"
        text = (
            "first https://example.org/p?t=DEAD middle https://example.org/p?t=DEAD end"
        )
        result = redact_url_in_text(text, url)
        assert "DEAD" not in result
        assert result.count("https://example.org/p?<redacted>") == 2

    def test_returns_text_unchanged_when_url_not_present(self):
        text = "ConnectionError: connection reset by peer"
        assert redact_url_in_text(text, "https://nowhere.example.org/") == text

    @pytest.mark.parametrize(
        ("text", "url", "expected"),
        [
            ("", "https://x", ""),
            (None, "https://x", ""),
            ("plain text", None, "plain text"),
            ("plain text", "", "plain text"),
        ],
    )
    def test_defensive_empty_inputs(self, text, url, expected):
        assert redact_url_in_text(text, url) == expected

    def test_non_string_text_is_coerced(self):
        # ``str(exc)`` is the common case but the helper must accept
        # any input that can be coerced to ``str`` (e.g. a future
        # ``requests`` exception subclass with a non-``str`` payload).
        class _Exc:
            def __str__(self) -> str:
                return "ConnectionError to https://example.org/path?s=X"

        result = redact_url_in_text(_Exc(), "https://example.org/path?s=X")
        assert "?s=X" not in result
        assert "https://example.org/path?<redacted>" in result
