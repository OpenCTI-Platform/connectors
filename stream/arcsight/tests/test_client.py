from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from arcsight_client import ArcSightClient
from arcsight_client.stix_patterns import extract_value


def _make_client() -> ArcSightClient:
    arcsight = SimpleNamespace(
        api_base_url="https://arcsight.example.com:8443",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        active_list_id="ABC123",
        value_column="value",
        ssl_verify=True,
    )
    client = ArcSightClient(SimpleNamespace(arcsight=arcsight), MagicMock())
    client.session = MagicMock()
    return client


def _login_response(token: str = "TOKEN") -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"log.loginResponse": {"log.return": token}}
    response.raise_for_status.return_value = None
    return response


def _ok_response() -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    return response


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("[ipv4-addr:value = '198.51.100.1']", "198.51.100.1"),
        ("[ipv6-addr:value = '2001:db8::1']", "2001:db8::1"),
        ("[domain-name:value = 'evil.example.com']", "evil.example.com"),
        ("[url:value = 'http://evil.example.com/x']", "http://evil.example.com/x"),
        ("[file:hashes.'SHA-256' = 'abc']", "abc"),
        ("[file:hashes.MD5 = 'def']", "def"),
        ("[email-addr:value = 'a@b.com']", None),
        ("garbage", None),
    ],
)
def test_extract_value(pattern, expected):
    assert extract_value(pattern) == expected


def test_add_indicator_logs_in_then_adds():
    client = _make_client()
    client.session.request.side_effect = [_login_response("TOKEN"), _ok_response()]

    assert (
        client.add_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"}) is True
    )

    login_call, add_call = client.session.request.call_args_list
    assert login_call.args[0] == "get"
    assert add_call.args[0] == "post"
    body = add_call.kwargs["json"]["act.addEntries"]
    assert body["act.authToken"] == "TOKEN"
    assert body["act.resourceId"] == "ABC123"
    assert body["act.entryList"]["entryList"] == [{"entry": ["198.51.100.1"]}]


def test_add_indicator_skips_unsupported():
    client = _make_client()
    assert client.add_indicator({"pattern": "[email-addr:value = 'a@b.com']"}) is False
    client.session.request.assert_not_called()


def test_token_is_cached_across_calls():
    client = _make_client()
    client.session.request.side_effect = [
        _login_response("TOKEN"),
        _ok_response(),
        _ok_response(),
    ]

    client.add_indicator({"pattern": "[ipv4-addr:value = '1.1.1.1']"})
    client.add_indicator({"pattern": "[ipv4-addr:value = '2.2.2.2']"})

    methods = [c.args[0] for c in client.session.request.call_args_list]
    assert methods == ["get", "post", "post"]  # single login


def test_remove_indicator_calls_delete_entries():
    client = _make_client()
    client.session.request.side_effect = [_login_response("TOKEN"), _ok_response()]

    assert (
        client.remove_indicator({"pattern": "[ipv4-addr:value = '198.51.100.1']"})
        is True
    )
    delete_call = client.session.request.call_args_list[1]
    assert "act.deleteEntries" in delete_call.kwargs["json"]


def test_login_failure_returns_false():
    client = _make_client()
    bad_login = MagicMock()
    bad_login.status_code = 200
    bad_login.json.return_value = {}
    bad_login.raise_for_status.return_value = None
    client.session.request.return_value = bad_login

    assert client.add_indicator({"pattern": "[ipv4-addr:value = '1.1.1.1']"}) is False


def test_post_entries_reauthenticates_on_failure():
    client = _make_client()
    client._token = "OLD"
    with patch.object(
        client,
        "_request",
        side_effect=[None, _login_response("NEW"), _ok_response()],
    ):
        from arcsight_client.api_client import ADD_ENTRIES_PATH

        assert (
            client._post_entries(ADD_ENTRIES_PATH, "act.addEntries", "1.1.1.1") is True
        )


def test_request_retries_on_rate_limit():
    client = _make_client()
    rate_limited = MagicMock()
    rate_limited.status_code = 429
    client.session.request.side_effect = [rate_limited, _ok_response()]

    with patch("arcsight_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/x")

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_returns_none_on_error():
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")

    with patch("arcsight_client.api_client.time.sleep"):
        assert client._request("get", "/x") is None


def test_request_fails_fast_on_4xx_without_retry():
    client = _make_client()
    unauthorized = MagicMock()
    unauthorized.status_code = 401
    unauthorized.raise_for_status.side_effect = requests.HTTPError("401")
    client.session.request.return_value = unauthorized

    with patch("arcsight_client.api_client.time.sleep") as sleep:
        assert client._request("post", "/x") is None

    # No retry on a non-retriable 4xx: a single call and no backoff sleep.
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    server_error = MagicMock()
    server_error.status_code = 503
    client.session.request.side_effect = [server_error, _ok_response()]

    with patch("arcsight_client.api_client.time.sleep") as sleep:
        assert client._request("get", "/x") is not None

    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_error_logging_excludes_exception_string():
    # A requests exception string typically embeds the full request URL, which for
    # the login call carries the password as a query parameter. _request must log
    # only the path / status code / exception type, never str(err).
    client = _make_client()
    secret = "S3CR3T-P4SSWORD-MARKER"
    client.session.request.side_effect = requests.ConnectionError(
        f"Failed for url: /LoginService/login?login=u&password={secret}"
    )

    with patch("arcsight_client.api_client.time.sleep"):
        client._request(
            "get",
            "/www/core-service/rest/LoginService/login",
            params={"login": "u", "password": secret},
        )

    logged = " ".join(
        str(call) for call in client.helper.connector_logger.warning.call_args_list
    )
    assert secret not in logged
    assert "ConnectionError" in logged


def test_request_http_error_logs_status_without_exception_string():
    client = _make_client()
    forbidden = MagicMock()
    forbidden.status_code = 403
    secret = "TOKEN-IN-URL-12345"
    forbidden.raise_for_status.side_effect = requests.HTTPError(
        f"403 for url: /login?password={secret}"
    )
    client.session.request.return_value = forbidden

    with patch("arcsight_client.api_client.time.sleep"):
        assert client._request("get", "/x") is None

    logged = " ".join(
        str(call) for call in client.helper.connector_logger.warning.call_args_list
    )
    assert secret not in logged
    assert "403" in logged
