from unittest.mock import MagicMock

import pytest
from doppel.client_api import ConnectorClient


@pytest.fixture
def client():
    helper = MagicMock()
    config = MagicMock()
    # Pydantic's HttpUrl serializes a path-like base URL with a trailing slash.
    config.doppel.api_base_url = "https://api.doppel.test/v1/"
    config.doppel.alerts_endpoint = "/alerts"
    config.doppel.api_key = "test-api-key"
    config.doppel.user_api_key = None
    config.doppel.organization_code = None
    config.doppel.retry_delay = 0
    config.doppel.max_retries = 1

    return ConnectorClient(helper=helper, config=config)


def _response(payload):
    response = MagicMock()
    response.json.return_value = payload
    return response


def test_client_sets_attribution_headers(client):
    assert client.session.headers["x-doppel-client"] == "opencti/7.260901.0"
    assert client.session.headers["User-Agent"] == "doppel-opencti/7.260901.0"


@pytest.mark.parametrize(
    ("total_pages", "expected_pages"),
    [
        (0, [0]),
        (1, [0]),
        (3, [0, 1, 2]),
    ],
)
def test_get_alerts_fetches_each_zero_indexed_page_once(
    client, total_pages, expected_pages
):
    def request_data(_url, params):
        page = params["page"]
        return _response(
            {
                "alerts": [{"id": f"alert-{page}"}] if total_pages else [],
                "metadata": {"total_pages": total_pages},
            }
        )

    client._request_data = MagicMock(side_effect=request_data)
    client._request_data.retry = MagicMock()

    alerts = client.get_alerts("2026-08-03T00:00:00Z")

    requested_pages = sorted(
        call.kwargs["params"]["page"] for call in client._request_data.call_args_list
    )
    assert requested_pages == expected_pages
    assert {call.args[0] for call in client._request_data.call_args_list} == {
        "https://api.doppel.test/v1/alerts"
    }
    assert sorted(alert["id"] for alert in alerts) == [
        f"alert-{page}" for page in expected_pages if total_pages
    ]


def test_get_alerts_continues_from_requested_start_page(client):
    def request_data(_url, params):
        page = params["page"]
        return _response(
            {
                "alerts": [{"id": f"alert-{page}"}],
                "metadata": {"total_pages": 4},
            }
        )

    client._request_data = MagicMock(side_effect=request_data)
    client._request_data.retry = MagicMock()

    alerts = client.get_alerts("2026-08-03T00:00:00Z", page=2)

    requested_pages = sorted(
        call.kwargs["params"]["page"] for call in client._request_data.call_args_list
    )
    assert requested_pages == [2, 3]
    assert sorted(alert["id"] for alert in alerts) == ["alert-2", "alert-3"]
