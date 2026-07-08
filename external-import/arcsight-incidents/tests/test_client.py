from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from arcsight_client import ArcSightClient


def _make_client(max_cases: int = 200) -> ArcSightClient:
    arcsight = SimpleNamespace(
        api_base_url="https://arcsight.example.com:8443",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        max_cases=max_cases,
        ssl_verify=True,
    )
    client = ArcSightClient(SimpleNamespace(arcsight_incidents=arcsight), MagicMock())
    client.session = MagicMock()
    return client


def _json_response(payload) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_extract_ids_variants():
    assert ArcSightClient._extract_ids(
        {"cas.findAllIdsResponse": {"cas.return": ["a", "b"]}}
    ) == ["a", "b"]
    assert ArcSightClient._extract_ids(
        {"cas.findAllIdsResponse": {"cas.return": "single"}}
    ) == ["single"]
    assert ArcSightClient._extract_ids(["x"]) == ["x"]
    assert ArcSightClient._extract_ids({"unexpected": 1}) == []


def test_extract_case_variants():
    assert ArcSightClient._extract_case(
        {"cas.getResourceByIdResponse": {"cas.return": {"name": "Case A"}}}
    ) == {"name": "Case A"}
    assert ArcSightClient._extract_case({"name": "Flat case"}) == {"name": "Flat case"}
    assert ArcSightClient._extract_case({"unexpected": 1}) is None


def test_extract_event_ids_variants():
    assert ArcSightClient._extract_event_ids({"eventIDs": ["a", "b"]}) == ["a", "b"]
    assert ArcSightClient._extract_event_ids({"baseEventIds": "single"}) == ["single"]
    assert ArcSightClient._extract_event_ids({"eventIDs": ["a", None, ""]}) == ["a"]
    assert ArcSightClient._extract_event_ids({"unexpected": 1}) == []


def test_extract_events_variants():
    assert ArcSightClient._extract_events(
        {"sev.getSecurityEventsResponse": {"sev.return": [{"name": "e"}]}}
    ) == [{"name": "e"}]
    assert ArcSightClient._extract_events(
        {"sev.getSecurityEventsResponse": {"sev.return": {"name": "e"}}}
    ) == [{"name": "e"}]
    assert ArcSightClient._extract_events({"unexpected": 1}) == []


def test_get_case_events_happy_path():
    client = _make_client()
    client._token = "TOKEN"
    client.session.request.return_value = _json_response(
        {"sev.getSecurityEventsResponse": {"sev.return": [{"name": "e1"}]}}
    )

    events = client.get_case_events({"eventIDs": ["e1"]})
    assert events == [{"name": "e1"}]


def test_get_case_events_no_ids_skips_request():
    client = _make_client()
    assert client.get_case_events({"name": "Case without events"}) == []
    client.session.request.assert_not_called()


def test_get_cases_happy_path():
    client = _make_client()
    client.session.request.side_effect = [
        _json_response({"log.loginResponse": {"log.return": "TOKEN"}}),
        _json_response({"cas.findAllIdsResponse": {"cas.return": ["id1"]}}),
        _json_response(
            {"cas.getResourceByIdResponse": {"cas.return": {"name": "Case A"}}}
        ),
    ]

    cases = client.get_cases()
    assert cases == [{"name": "Case A"}]
    assert client.session.request.call_count == 3


def test_get_cases_returns_empty_when_login_fails():
    client = _make_client()
    bad_login = _json_response({})  # no token keys
    client.session.request.return_value = bad_login
    assert client.get_cases() == []


def test_get_cases_reauthenticates_on_failure():
    client = _make_client()
    with patch.object(client, "_get_token", return_value="TOKEN"), patch.object(
        client, "_find_ids", side_effect=[None, ["id1"]]
    ), patch.object(client, "_get_case", return_value={"name": "Case A"}):
        cases = client.get_cases()
    assert cases == [{"name": "Case A"}]


def test_get_cases_respects_max_cases():
    client = _make_client(max_cases=1)
    with patch.object(client, "_get_token", return_value="TOKEN"), patch.object(
        client, "_find_ids", return_value=["id1", "id2", "id3"]
    ), patch.object(client, "_get_case", return_value={"name": "Case"}) as get_case:
        client.get_cases()
    assert get_case.call_count == 1


def test_request_retries_on_rate_limit():
    client = _make_client()
    rate_limited = MagicMock()
    rate_limited.status_code = 429
    client.session.request.side_effect = [rate_limited, _json_response({})]

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
        assert client._request("get", "/x") is None

    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    server_error = MagicMock()
    server_error.status_code = 503
    client.session.request.side_effect = [server_error, _json_response({})]

    with patch("arcsight_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/x")

    assert result is not None
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
