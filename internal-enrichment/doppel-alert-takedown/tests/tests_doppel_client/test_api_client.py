from unittest.mock import MagicMock

from doppel_client.api_client import DoppelClient


def _response(
    *,
    status_code: int = 200,
    payload: dict | None = None,
) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.content = b"{}"
    response.json.return_value = payload or {"id": "ACM-1234"}
    return response


def test_v1_uses_static_headers_and_normalized_v1_url():
    client = DoppelClient(
        helper=MagicMock(),
        base_url="https://api.doppel.test/v1",
        api_key="api-key",
        user_api_key="user-api-key",
    )

    assert client.session.headers["x-api-key"] == "api-key"
    assert client.session.headers["x-user-api-key"] == "user-api-key"
    assert client.session.headers["x-doppel-client"] == "opencti/7.260901.0"
    assert client.session.headers["User-Agent"] == "doppel-opencti/7.260901.0"
    assert "Authorization" not in client.session.headers

    client.session = MagicMock()
    client.session.post.return_value = _response()
    client.create_alert("https://example.test", "url")

    assert client.session.post.call_args.args[0] == "https://api.doppel.test/v1/alert"


def test_v2_mints_token_and_uses_bearer_auth():
    client = DoppelClient(
        helper=MagicMock(),
        base_url="https://api.doppel.test/v1",
        api_version="v2",
        client_id="client-id",
        client_secret="client-secret",
    )
    assert client.oauth_token_provider is not None
    assert client.oauth_token_provider.token_url == (
        "https://api.doppel.test/oauth/token"
    )
    assert "x-api-key" not in client.session.headers
    assert "x-user-api-key" not in client.session.headers
    assert client.session.headers["x-doppel-client"] == "opencti/7.260901.0"
    assert client.session.headers["User-Agent"] == "doppel-opencti/7.260901.0"

    token_session = MagicMock()
    token_session.post.return_value = _response(
        payload={
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 86400,
        }
    )
    client.oauth_token_provider.session = token_session

    client.session = MagicMock()
    client.session.post.return_value = _response()
    client.create_alert("https://example.test", "url")

    call = client.session.post.call_args
    assert call.args[0] == "https://api.doppel.test/v2/alert"
    assert call.kwargs["headers"] == {"Authorization": "Bearer access-token"}
    token_session.post.assert_called_once()


def test_v2_refreshes_once_after_unauthorized():
    client = DoppelClient(
        helper=MagicMock(),
        base_url="https://api.doppel.test",
        api_version="v2",
        client_id="client-id",
        client_secret="client-secret",
    )
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
    client.session.put.side_effect = [unauthorized, _response()]

    client.request_takedown("https://example.test", "Confirmed phishing.")

    assert client.session.put.call_count == 2
    assert client.session.put.call_args_list[0].kwargs["headers"] == {
        "Authorization": "Bearer token-1"
    }
    assert client.session.put.call_args_list[1].kwargs["headers"] == {
        "Authorization": "Bearer token-2"
    }
    unauthorized.close.assert_called_once()
