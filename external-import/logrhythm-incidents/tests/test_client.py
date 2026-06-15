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


def test_extract_cases_variants():
    assert LogRhythmClient._extract_cases([{"id": 1}]) == [{"id": 1}]
    assert LogRhythmClient._extract_cases({"cases": [{"id": 2}]}) == [{"id": 2}]
    assert LogRhythmClient._extract_cases({"unexpected": 1}) == []


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
