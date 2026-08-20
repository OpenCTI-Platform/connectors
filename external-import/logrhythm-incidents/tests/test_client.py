from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from logrhythm_client import LogRhythmClient


def _make_client() -> LogRhythmClient:
    logrhythm = SimpleNamespace(
        api_base_url="https://logrhythm.example.com:8501",
        api_token=SimpleNamespace(get_secret_value=lambda: "tok"),
        max_cases=200,
        ssl_verify=True,
    )
    client = LogRhythmClient(
        SimpleNamespace(logrhythm_incidents=logrhythm), MagicMock()
    )
    client.session = MagicMock()
    return client


def _response(payload) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_extract_list_variants():
    assert LogRhythmClient._extract_list([{"id": 1}], ("cases",)) == [{"id": 1}]
    assert LogRhythmClient._extract_list({"cases": [{"id": 2}]}, ("cases",)) == [
        {"id": 2}
    ]
    assert LogRhythmClient._extract_list({"alarms": [{"id": 3}]}, ("alarms",)) == [
        {"id": 3}
    ]
    assert LogRhythmClient._extract_list({"unexpected": 1}, ("cases",)) == []


def test_get_case_alarms():
    client = _make_client()
    client.session.request.return_value = _response([{"alarmId": "a1"}])

    alarms = client.get_case_alarms("c1")
    assert alarms == [{"alarmId": "a1"}]
    call = client.session.request.call_args
    assert call.args[1].endswith("/lr-case-api/cases/c1/evidence/alarms")


def test_get_cases_happy_path():
    client = _make_client()
    client.session.request.return_value = _response([{"number": "1"}])

    cases = client.get_cases()
    assert cases == [{"number": "1"}]
    call = client.session.request.call_args
    assert call.args[0] == "get"
    assert call.args[1].endswith("/lr-case-api/cases")
    assert call.kwargs["params"]["count"] == 200


def test_get_cases_returns_empty_on_error():
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")
    with patch("logrhythm_client.api_client.time.sleep"):
        assert client.get_cases() == []


def test_request_retries_on_rate_limit():
    client = _make_client()
    rate_limited = MagicMock()
    rate_limited.status_code = 429
    client.session.request.side_effect = [rate_limited, _response([])]

    with patch("logrhythm_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/lr-case-api/cases")

    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_fails_fast_on_4xx_without_retry():
    client = _make_client()
    unauthorized = MagicMock()
    unauthorized.status_code = 401
    unauthorized.raise_for_status.side_effect = requests.HTTPError("401")
    client.session.request.return_value = unauthorized

    with patch("logrhythm_client.api_client.time.sleep") as sleep:
        assert client._request("get", "/lr-case-api/cases") is None

    # No retry on a non-retriable 4xx: a single call and no backoff sleep.
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    server_error = MagicMock()
    server_error.status_code = 503
    client.session.request.side_effect = [server_error, _response([])]

    with patch("logrhythm_client.api_client.time.sleep") as sleep:
        assert client._request("get", "/lr-case-api/cases") is not None

    assert client.session.request.call_count == 2
    sleep.assert_called_once()
