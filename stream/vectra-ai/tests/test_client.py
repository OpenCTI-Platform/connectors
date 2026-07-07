from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from vectra_client import VectraClient
from vectra_client.stix_builder import (
    build_stix_package,
    extract_indicator,
    is_supported_pattern,
)

# ---------------------------------------------------------------------------
# stix_builder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("[ipv4-addr:value = '198.51.100.1']", ("ipv4-addr", "198.51.100.1")),
        ("[ipv6-addr:value = '2001:db8::1']", ("ipv6-addr", "2001:db8::1")),
        (
            "[domain-name:value = 'evil.example.com']",
            ("domain-name", "evil.example.com"),
        ),
        (
            "[url:value = 'http://evil.example.com/x']",
            ("url", "http://evil.example.com/x"),
        ),
        ("  [ipv4-addr:value = '203.0.113.5']  ", ("ipv4-addr", "203.0.113.5")),
    ],
)
def test_extract_indicator_supported(pattern, expected):
    assert extract_indicator(pattern) == expected
    assert is_supported_pattern(pattern) is True


@pytest.mark.parametrize(
    "pattern",
    [
        "[file:hashes.SHA-256 = 'aa']",
        "[file:hashes.MD5 = 'aa']",
        "[email-addr:value = 'a@b.com']",
        "[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'x.com']",
        "garbage",
        "",
    ],
)
def test_extract_indicator_unsupported(pattern):
    assert extract_indicator(pattern) is None
    assert is_supported_pattern(pattern) is False


def test_build_stix_package_ipv4():
    document = build_stix_package([("ipv4-addr", "198.51.100.1")])
    assert document.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert 'version="1.2"' in document
    assert "stix:STIX_Package" in document
    assert 'xsi:type="AddressObj:AddressObjectType"' in document
    assert 'category="ipv4-addr"' in document
    assert (
        "<AddressObj:Address_Value>198.51.100.1</AddressObj:Address_Value>" in document
    )


def test_build_stix_package_domain():
    document = build_stix_package([("domain-name", "evil.example.com")])
    assert 'xsi:type="DomainNameObj:DomainNameObjectType"' in document
    assert "<DomainNameObj:Value>evil.example.com</DomainNameObj:Value>" in document


def test_build_stix_package_url():
    document = build_stix_package([("url", "http://evil.example.com/x")])
    assert 'xsi:type="URIObj:URIObjectType"' in document
    assert "<URIObj:Value>http://evil.example.com/x</URIObj:Value>" in document


def test_build_stix_package_escapes_values():
    document = build_stix_package([("domain-name", "a&b<c>.com")])
    assert "a&amp;b&lt;c&gt;.com" in document
    assert "<c>.com" not in document


# ---------------------------------------------------------------------------
# VectraClient
# ---------------------------------------------------------------------------


def _make_client() -> VectraClient:
    vectra_ai = SimpleNamespace(
        api_base_url="https://vectra.example.com",
        api_token=SimpleNamespace(get_secret_value=lambda: "token"),
        api_version="v2.5",
        feed_name="OpenCTI",
        feed_category="cnc",
        feed_certainty="High",
        feed_duration=14,
        ssl_verify=True,
    )
    config = SimpleNamespace(vectra_ai=vectra_ai)
    client = VectraClient(config, MagicMock())
    client.session = MagicMock()
    return client


def _response(status: int = 200, payload: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload if payload is not None else {}
    response.raise_for_status.return_value = None
    return response


def test_endpoint_builds_versioned_url():
    client = _make_client()
    assert (
        client._endpoint("threatFeeds", "42")
        == "https://vectra.example.com/api/v2.5/threatFeeds/42"
    )


def test_get_or_create_feed_returns_existing_feed():
    client = _make_client()
    client.session.request.return_value = _response(
        200, {"threatFeeds": [{"id": "42", "name": "OpenCTI"}]}
    )

    assert client.get_or_create_feed() == "42"
    assert client.session.request.call_count == 1
    assert client.session.request.call_args.args[0] == "get"


def test_get_or_create_feed_creates_when_missing():
    client = _make_client()
    client.session.request.side_effect = [
        _response(200, {"threatFeeds": []}),
        _response(201, {"threatFeed": {"id": "99", "name": "OpenCTI"}}),
    ]

    assert client.get_or_create_feed() == "99"
    assert client.session.request.call_count == 2
    assert client.session.request.call_args_list[1].args[0] == "post"


def test_get_or_create_feed_is_cached():
    client = _make_client()
    client._feed_id = "7"

    assert client.get_or_create_feed() == "7"
    client.session.request.assert_not_called()


def test_get_or_create_feed_retries_after_transient_failure():
    # A failed resolution must not be cached: the next call retries and resolves
    # the feed instead of short-circuiting for the connector's lifetime.
    client = _make_client()
    client.session.request.side_effect = [
        _response(200, {"threatFeeds": []}),  # 1st call: list -> nothing
        _response(200, {}),  # 1st call: create -> no id (transient failure)
        _response(  # 2nd call: list now returns the feed
            200, {"threatFeeds": [{"id": "55", "name": "OpenCTI"}]}
        ),
    ]

    assert client.get_or_create_feed() is None
    assert client._feed_id is None
    assert client.get_or_create_feed() == "55"
    assert client._feed_id == "55"


def test_add_indicator_skips_unsupported_pattern():
    client = _make_client()

    result = client.add_indicator({"pattern": "[file:hashes.SHA-256 = 'aa']"})

    assert result is False
    client.session.request.assert_not_called()


def test_add_indicator_uploads_supported_indicator():
    client = _make_client()
    client._feed_id = "42"
    client.session.request.return_value = _response(200, {})

    result = client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})

    assert result is True
    call = client.session.request.call_args
    assert call.args[0] == "post"
    assert call.args[1] == "https://vectra.example.com/api/v2.5/threatFeeds/42"
    assert "files" in call.kwargs
