from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from doppel.client_api import ConnectorClient
from pydantic import SecretStr


@pytest.fixture
def client():
    return ConnectorClient(helper=MagicMock(), config=_config(api_version="v1"))


def _response(payload=None, *, status_code: int = 200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {
        "metadata": {"total_pages": 0},
        "alerts": [],
    }
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


def _config(*, api_version: str) -> SimpleNamespace:
    return SimpleNamespace(
        doppel=SimpleNamespace(
            api_base_url="https://api.doppel.test/v1/",
            api_version=api_version,
            api_key=SecretStr("api-key") if api_version == "v1" else None,
            user_api_key=(SecretStr("user-api-key") if api_version == "v1" else None),
            organization_code="ACM" if api_version == "v1" else None,
            client_id="client-id" if api_version == "v2" else None,
            client_secret=(SecretStr("client-secret") if api_version == "v2" else None),
            token_url=None,
            token_audience="doppel-external",
            alerts_endpoint="/v1/alerts",
            retry_delay=0,
            max_retries=1,
        )
    )


def test_v1_uses_static_headers_and_normalized_v1_url():
    helper = MagicMock()
    client = ConnectorClient(helper, _config(api_version="v1"))

    assert client.session.headers["x-api-key"] == "api-key"
    assert client.session.headers["x-user-api-key"] == "user-api-key"
    assert client.session.headers["x-organization-code"] == "ACM"
    assert client.session.headers["x-doppel-client"] == "opencti/7.260901.0"
    assert client.session.headers["User-Agent"] == "doppel-opencti/7.260901.0"
    assert "Authorization" not in client.session.headers

    client.session = MagicMock()
    client.session.get.return_value = _response()
    client.get_alerts("2026-08-01T00:00:00", page_size=100)

    assert client.session.get.call_args.args[0] == "https://api.doppel.test/v1/alerts"


def test_v2_mints_token_and_uses_only_bearer_auth():
    helper = MagicMock()
    client = ConnectorClient(helper, _config(api_version="v2"))
    assert client.oauth_token_provider is not None
    assert client.oauth_token_provider.token_url == (
        "https://api.doppel.test/oauth/token"
    )
    assert "x-api-key" not in client.session.headers
    assert "x-user-api-key" not in client.session.headers
    assert "x-organization-code" not in client.session.headers
    assert client.session.headers["x-doppel-client"] == "opencti/7.260901.0"
    assert client.session.headers["User-Agent"] == "doppel-opencti/7.260901.0"

    token_response = _response(
        payload={
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 86400,
        }
    )
    token_session = MagicMock()
    token_session.post.return_value = token_response
    client.oauth_token_provider.session = token_session

    client.session = MagicMock()
    client.session.get.return_value = _response()
    client.get_alerts("2026-08-01T00:00:00", page_size=100)

    call = client.session.get.call_args
    assert call.args[0] == "https://api.doppel.test/v2/alerts"
    assert call.kwargs["headers"] == {"Authorization": "Bearer access-token"}
    token_session.post.assert_called_once()


def test_v2_refreshes_once_after_unauthorized():
    client = ConnectorClient(MagicMock(), _config(api_version="v2"))
    assert client.oauth_token_provider is not None

    token_session = MagicMock()
    token_session.post.side_effect = [
        _response(
            payload={
                "access_token": "token-1",
                "token_type": "Bearer",
                "expires_in": 86400,
            }
        ),
        _response(
            payload={
                "access_token": "token-2",
                "token_type": "Bearer",
                "expires_in": 86400,
            }
        ),
    ]
    client.oauth_token_provider.session = token_session

    unauthorized = _response(status_code=401)
    client.session = MagicMock()
    client.session.get.side_effect = [unauthorized, _response()]

    client.get_alerts("2026-08-01T00:00:00", page_size=100)

    assert token_session.post.call_count == 2
    assert client.session.get.call_count == 2
    assert client.session.get.call_args_list[0].kwargs["headers"] == {
        "Authorization": "Bearer token-1"
    }
    assert client.session.get.call_args_list[1].kwargs["headers"] == {
        "Authorization": "Bearer token-2"
    }
    unauthorized.close.assert_called_once()
