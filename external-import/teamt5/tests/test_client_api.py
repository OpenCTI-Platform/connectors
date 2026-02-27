from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import requests
from teamt5.client_api import _OAUTH_TOKEN_URL, ConnectorClient


def _make_token_response(access_token="tok123", expires_in=3600):
    resp = Mock()
    resp.json.return_value = {"access_token": access_token, "expires_in": expires_in}
    resp.raise_for_status = Mock()
    return resp


class TestInitStaticKey:
    def test_init_static_key_sets_header(self, mock_helper, mock_config_api_key):
        """With api_key set, session header is Bearer <key>; no OAuth call made."""
        with (
            patch("teamt5.client_api.requests.Session") as mock_session_cls,
            patch("teamt5.client_api.requests.post") as mock_post,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            ConnectorClient(mock_helper, mock_config_api_key)

            mock_session.headers.update.assert_called_once_with(
                {"Authorization": "Bearer test-key"}
            )
            mock_post.assert_not_called()


class TestInitOAuth:
    def test_init_oauth_fetches_token(self, mock_helper, mock_config_oauth):
        """With client_id/client_secret, a POST to /oauth/token is made on init."""
        token_resp = _make_token_response("oauth-token", 3600)

        with (
            patch(
                "teamt5.client_api.requests.post", return_value=token_resp
            ) as mock_post,
            patch("teamt5.client_api.requests.Session") as mock_session_cls,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            client = ConnectorClient(mock_helper, mock_config_oauth)

            mock_post.assert_called_once_with(
                _OAUTH_TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": "cid",
                    "client_secret": "csecret",
                },
                timeout=10,
            )
            mock_session.headers.update.assert_called_with(
                {"Authorization": "Bearer oauth-token"}
            )
            assert client._token == "oauth-token"

    def test_oauth_takes_precedence_over_api_key(self, mock_helper):
        """When both OAuth credentials and api_key are set, OAuth wins."""
        token_resp = _make_token_response("oauth-token", 3600)
        config = Mock()
        config.api_key = "legacy-key"
        config.client_id = "cid"
        config.client_secret = "csecret"

        with (
            patch(
                "teamt5.client_api.requests.post", return_value=token_resp
            ) as mock_post,
            patch("teamt5.client_api.requests.Session") as mock_session_cls,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            client = ConnectorClient(mock_helper, config)

            mock_post.assert_called_once()
            mock_session.headers.update.assert_called_with(
                {"Authorization": "Bearer oauth-token"}
            )
            assert client._token == "oauth-token"


class TestEnsureValidToken:
    def _make_client(self, mock_helper, mock_config_oauth):
        token_resp = _make_token_response("initial-token", 3600)
        with (
            patch("teamt5.client_api.requests.post", return_value=token_resp),
            patch("teamt5.client_api.requests.Session"),
        ):
            return ConnectorClient(mock_helper, mock_config_oauth)

    def test_oauth_token_refresh_when_expired(self, mock_helper, mock_config_oauth):
        """_ensure_valid_token() re-fetches when _token_expires_at is in the past."""
        client = self._make_client(mock_helper, mock_config_oauth)
        client._token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        refresh_resp = _make_token_response("refreshed-token", 3600)
        with patch(
            "teamt5.client_api.requests.post", return_value=refresh_resp
        ) as mock_post:
            client._ensure_valid_token()

        mock_post.assert_called_once()
        assert client._token == "refreshed-token"

    def test_oauth_no_refresh_when_valid(self, mock_helper, mock_config_oauth):
        """_ensure_valid_token() skips re-fetch when token is still valid."""
        client = self._make_client(mock_helper, mock_config_oauth)
        client._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        with patch("teamt5.client_api.requests.post") as mock_post:
            client._ensure_valid_token()

        mock_post.assert_not_called()

    def test_static_key_ensure_valid_token_is_noop(
        self, mock_helper, mock_config_api_key
    ):
        """_ensure_valid_token() is a no-op for static api_key mode."""
        with (
            patch("teamt5.client_api.requests.Session"),
            patch("teamt5.client_api.requests.post") as mock_post,
        ):
            client = ConnectorClient(mock_helper, mock_config_api_key)
            mock_post.reset_mock()
            client._ensure_valid_token()

        mock_post.assert_not_called()


class TestRequestData:
    def _make_client(self, mock_helper, mock_config_api_key):
        with patch("teamt5.client_api.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            client = ConnectorClient(mock_helper, mock_config_api_key)
            client.session = mock_session
            return client

    def test_request_data_success(self, mock_helper, mock_config_api_key):
        """_request_data() returns response on 200."""
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        client.session.get.return_value = mock_resp

        result = client._request_data("https://api.threatvision.org/test")

        assert result is mock_resp

    def test_request_data_http_error(self, mock_helper, mock_config_api_key):
        """_request_data() returns None and logs on 4xx/5xx."""
        client = self._make_client(mock_helper, mock_config_api_key)

        http_err = requests.HTTPError("404 Not Found")
        client.session.get.side_effect = http_err

        result = client._request_data("https://api.threatvision.org/test")

        assert result is None
        mock_helper.connector_logger.error.assert_called_once()

    def test_request_data_calls_ensure_valid_token(
        self, mock_helper, mock_config_api_key
    ):
        """_ensure_valid_token() is called before each request."""
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        client.session.get.return_value = mock_resp

        with patch.object(client, "_ensure_valid_token") as mock_ensure:
            client._request_data("https://api.threatvision.org/test")

        mock_ensure.assert_called_once()
