from unittest.mock import MagicMock, patch

import pytest
import requests
from corelight_investigator_client import (
    CorelightInvestigatorAPIError,
    CorelightInvestigatorClient,
)


def _make_client() -> CorelightInvestigatorClient:
    client = CorelightInvestigatorClient(
        MagicMock(),
        api_base_url="https://eu.api.investigator.corelight.com",
        api_key="key",
        alerts_path="/api/v1/alerts",
    )
    client.session = MagicMock()
    return client


def _response(payload, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_extract_alerts_variants():
    assert CorelightInvestigatorClient._extract_alerts([{"id": 1}]) == [{"id": 1}]
    assert CorelightInvestigatorClient._extract_alerts({"data": [{"id": 2}]}) == [
        {"id": 2}
    ]
    assert CorelightInvestigatorClient._extract_alerts({"alerts": [{"id": 3}]}) == [
        {"id": 3}
    ]
    assert CorelightInvestigatorClient._extract_alerts({"unexpected": 1}) == []


def test_get_alerts_returns_list():
    client = _make_client()
    client.session.request.return_value = _response({"data": [{"alert_id": "a"}]})
    assert client.get_alerts() == [{"alert_id": "a"}]


def test_get_alerts_passes_since():
    client = _make_client()
    client.session.request.return_value = _response({"data": []})

    client.get_alerts(since="2024-01-01T00:00:00.000Z")
    call = client.session.request.call_args
    assert call.kwargs["params"]["start_time"] == "2024-01-01T00:00:00.000Z"
    assert call.kwargs["params"]["limit"] == 1000


def test_get_alerts_raises_on_http_error():
    client = _make_client()
    err_response = MagicMock()
    err_response.status_code = 401
    bad = MagicMock()
    bad.status_code = 401
    bad.raise_for_status.side_effect = requests.HTTPError(response=err_response)
    client.session.request.return_value = bad

    with pytest.raises(CorelightInvestigatorAPIError):
        client.get_alerts()


def test_get_alerts_retries_on_rate_limit():
    client = _make_client()
    rate_limited = MagicMock()
    rate_limited.status_code = 429
    client.session.request.side_effect = [
        rate_limited,
        _response({"data": [{"alert_id": "a"}]}),
    ]

    with patch("corelight_investigator_client.api_client.time.sleep"):
        result = client.get_alerts()
    assert result == [{"alert_id": "a"}]
    assert client.session.request.call_count == 2
