from unittest.mock import MagicMock

import pytest
import requests
from connector.stairwell import StairwellClient
from connector.stairwell.client import DEFAULT_TIMEOUT, SUMMARIZE_TIMEOUT

BASE = "https://api.example"


def _response(status, body=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if isinstance(body, Exception):
        resp.json.side_effect = body
    else:
        resp.json.return_value = body
    return resp


def _client(response=None, **kwargs):
    client = StairwellClient(api_token="tok", base_url=BASE + "/", **kwargs)
    client._session.get = MagicMock(return_value=response or _response(200, {}))
    return client


def _requested_url(client):
    return client._session.get.call_args.args[0]


def test_empty_token_is_rejected():
    with pytest.raises(ValueError, match="Stairwell API token"):
        StairwellClient(api_token="")


def test_session_sends_auth_and_optional_rate_limit_headers():
    headers = StairwellClient(api_token="tok")._session.headers
    assert headers["Authorization"] == "Bearer tok"
    assert headers["X-Apikey"] == "tok"
    assert "Organization-Id" not in headers and "User-Id" not in headers
    headers = StairwellClient(
        api_token="tok", organization_id="org", user_id="usr"
    )._session.headers
    assert headers["Organization-Id"] == "org"
    assert headers["User-Id"] == "usr"


def test_session_retries_only_idempotent_gets_on_transient_statuses():
    retry = StairwellClient(api_token="tok")._session.get_adapter(BASE).max_retries
    assert retry.total == 3
    assert set(retry.allowed_methods) == {"GET"}
    assert set(retry.status_forcelist) == {429, 500, 502, 503, 504}


def test_default_base_url_and_trailing_slash():
    assert StairwellClient(api_token="tok")._base_url == "https://app.stairwell.com"
    assert _client()._base_url == BASE


@pytest.mark.parametrize(
    "call, path",
    [
        (lambda c: c.get_object_metadata("ab/c"), "/v1/objects/ab%2Fc/metadata"),
        (lambda c: c.summarize_file("abc"), "/v1/objects/abc:summarize"),
        (lambda c: c.get_variants("abc"), "/v202112/variants/abc"),
        (
            lambda c: c.list_objects_metadata('a == "b"', page_size=5),
            "/v1/objects/metadata?filter=a%20%3D%3D%20%22b%22&pageSize=5",
        ),
        (
            lambda c: c.list_objects_metadata("x", page_size=5, page_token="t/1"),
            "/v1/objects/metadata?filter=x&pageSize=5&pageToken=t%2F1",
        ),
        (
            lambda c: c.list_object_sightings("abc", page_size=7),
            "/v1/objects/abc/sightings?pageSize=7",
        ),
        (
            lambda c: c.list_object_sightings("abc", page_size=7, page_token="n&x"),
            "/v1/objects/abc/sightings?pageSize=7&pageToken=n%26x",
        ),
        (
            lambda c: c.get_hostname_metadata_v1("evil.example"),
            "/v1/hostnames/evil.example/metadata",
        ),
        (lambda c: c.get_hostname_v2("evil.example"), "/v2/hostnames/evil.example"),
        (
            lambda c: c.get_hostname_resolutions("evil.example"),
            "/v2/hostnames/evil.example/resolutions",
        ),
        (
            lambda c: c.get_hostname_resolutions(
                "evil.example",
                record_types="A,AAAA",
                interval_start="2026-01-01T00:00:00Z",
                interval_end="2026-02-01T00:00:00Z",
                include_errors=True,
            ),
            "/v2/hostnames/evil.example/resolutions?recordTypes=A%2CAAAA"
            "&interval.startTime=2026-01-01T00%3A00%3A00Z"
            "&interval.endTime=2026-02-01T00%3A00%3A00Z&includeErrors=true",
        ),
        (
            lambda c: c.get_hostname_whitelist_status("evil.example"),
            "/v2/hostnames/evil.example/whitelist-status",
        ),
        (lambda c: c.get_ip("2001:db8::1"), "/v2/ips/2001%3Adb8%3A%3A1"),
        (lambda c: c.get_ip_whois("1.2.3.4"), "/v2/ips/1.2.3.4/whois?view=FULL"),
        (lambda c: c.get_ip_hostnames("1.2.3.4"), "/v2/ips/1.2.3.4/hostnames"),
        (lambda c: c.get_asn_whois(64500), "/v2/asns/64500/whois?view=FULL"),
    ],
)
def test_endpoints_build_encoded_urls(call, path):
    client = _client()
    assert call(client) == (200, {})
    assert _requested_url(client) == BASE + path


def test_value_cannot_escape_its_path_segment():
    client = _client()
    client.get_object_metadata("../admin?x=1#f")
    assert (
        _requested_url(client) == BASE + "/v1/objects/..%2Fadmin%3Fx%3D1%23f/metadata"
    )


def test_summarize_gets_the_long_timeout_and_others_the_default():
    client = _client()
    client.summarize_file("abc")
    assert client._session.get.call_args.kwargs["timeout"] == SUMMARIZE_TIMEOUT
    client.get_ip("1.2.3.4")
    assert client._session.get.call_args.kwargs["timeout"] == DEFAULT_TIMEOUT


@pytest.mark.parametrize(
    "response, want",
    [
        (_response(200, {"ok": True}), (200, {"ok": True})),
        (_response(404, text="missing"), (404, None)),
        (_response(401, text="denied"), (401, None)),
        (_response(503, text="down"), (503, None)),
        (_response(200, ValueError("not json"), text="<html>"), (200, None)),
    ],
)
def test_response_handling_never_raises(response, want):
    assert _client(response).get_ip("1.2.3.4") == want


def test_transport_error_returns_status_zero():
    client = _client()
    client._session.get.side_effect = requests.ConnectionError("refused")
    assert client.get_ip("1.2.3.4") == (0, None)


@pytest.mark.parametrize(
    "call, value",
    [
        (lambda c: c.object_ui_url("a" * 64), "a" * 64),
        (lambda c: c.hostname_ui_url("evil.example"), "evil.example"),
        (lambda c: c.ip_ui_url("1.2.3.4"), "1.2.3.4"),
        (lambda c: c.asn_ui_url(64500), "64500"),
        (
            lambda c: c.url_ui_url("http://x/a?b=1&c=2"),
            "http%3A%2F%2Fx%2Fa%3Fb%3D1%26c%3D2",
        ),
    ],
)
def test_ui_links_are_encoded_search_urls(call, value):
    assert call(_client()) == f"{BASE}/search?search-query={value}"
