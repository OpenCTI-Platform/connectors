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
