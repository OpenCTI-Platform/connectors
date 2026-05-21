"""Unit tests for ``teamt5_services.client.Teamt5Client``.

The client supports two authentication paths:

* OAuth 2.0 client credentials (recommended) — exchanges
  ``client_id`` / ``client_secret`` for a Bearer token against
  ``<api_base_url>/oauth/token`` and refreshes it before expiry.
* Static API key (deprecated, kept for backwards compatibility) —
  uses the configured token as-is.

When both are configured OAuth takes precedence. ``request_data``
returns the decoded JSON body on success and ``None`` on transport
errors / invalid JSON, so the connector run can degrade gracefully
instead of crashing.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import requests
from teamt5_services.client import Teamt5Client


def _make_token_response(access_token="tok123", expires_in=3600):
    resp = Mock()
    resp.json.return_value = {
        "access_token": access_token,
        "expires_in": expires_in,
    }
    resp.raise_for_status = Mock()
    return resp


class TestInitStaticKey:
    def test_init_static_key_sets_header(self, mock_helper, mock_config_api_key):
        """With api_key set, session header is Bearer <key>; no OAuth call made."""
        with (
            patch("teamt5_services.client.requests.Session") as mock_session_cls,
            patch("teamt5_services.client.requests.post") as mock_post,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            Teamt5Client(mock_helper, mock_config_api_key)

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
                "teamt5_services.client.requests.post",
                return_value=token_resp,
            ) as mock_post,
            patch("teamt5_services.client.requests.Session") as mock_session_cls,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            client = Teamt5Client(mock_helper, mock_config_oauth)

            mock_post.assert_called_once_with(
                f"{mock_config_oauth.teamt5.api_base_url.rstrip('/')}/oauth/token",
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

    def test_oauth_takes_precedence_over_api_key(self, mock_helper, mock_config_both):
        """When both OAuth credentials and api_key are set, OAuth wins."""
        token_resp = _make_token_response("oauth-token", 3600)

        with (
            patch(
                "teamt5_services.client.requests.post",
                return_value=token_resp,
            ) as mock_post,
            patch("teamt5_services.client.requests.Session") as mock_session_cls,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            client = Teamt5Client(mock_helper, mock_config_both)

            mock_post.assert_called_once()
            mock_session.headers.update.assert_called_with(
                {"Authorization": "Bearer oauth-token"}
            )
            assert client._token == "oauth-token"


class TestEnsureValidToken:
    def _make_oauth_client(self, mock_helper, mock_config_oauth):
        token_resp = _make_token_response("initial-token", 3600)
        with (
            patch("teamt5_services.client.requests.post", return_value=token_resp),
            patch("teamt5_services.client.requests.Session"),
        ):
            return Teamt5Client(mock_helper, mock_config_oauth)

    def test_oauth_token_refresh_when_expired(self, mock_helper, mock_config_oauth):
        """_ensure_valid_token() re-fetches when _token_expires_at is in the past."""
        client = self._make_oauth_client(mock_helper, mock_config_oauth)
        client._token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        refresh_resp = _make_token_response("refreshed-token", 3600)
        with patch(
            "teamt5_services.client.requests.post", return_value=refresh_resp
        ) as mock_post:
            client._ensure_valid_token()

        mock_post.assert_called_once()
        assert client._token == "refreshed-token"

    def test_oauth_no_refresh_when_valid(self, mock_helper, mock_config_oauth):
        """_ensure_valid_token() skips re-fetch when token is still valid."""
        client = self._make_oauth_client(mock_helper, mock_config_oauth)
        client._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        with patch("teamt5_services.client.requests.post") as mock_post:
            client._ensure_valid_token()

        mock_post.assert_not_called()

    def test_static_key_ensure_valid_token_is_noop(
        self, mock_helper, mock_config_api_key
    ):
        """_ensure_valid_token() is a no-op for static api_key mode."""
        with (
            patch("teamt5_services.client.requests.Session"),
            patch("teamt5_services.client.requests.post") as mock_post,
        ):
            client = Teamt5Client(mock_helper, mock_config_api_key)
            mock_post.reset_mock()
            client._ensure_valid_token()

        mock_post.assert_not_called()


class TestRequestData:
    def _make_client(self, mock_helper, mock_config_api_key):
        with patch("teamt5_services.client.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            client = Teamt5Client(mock_helper, mock_config_api_key)
            client.session = mock_session
            return client

    def test_request_data_success_returns_json_body(
        self, mock_helper, mock_config_api_key
    ):
        """request_data() returns the decoded JSON body on 200."""
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.return_value = {"success": True, "reports": []}
        client.session.get.return_value = mock_resp

        with patch("teamt5_services.client.time.sleep"):
            result = client.request_data("https://api.threatvision.org/test")

        assert result == {"success": True, "reports": []}

    def test_request_data_http_error_returns_none_and_logs(
        self, mock_helper, mock_config_api_key
    ):
        """request_data() returns None and logs on 4xx/5xx."""
        client = self._make_client(mock_helper, mock_config_api_key)

        client.session.get.side_effect = requests.HTTPError("404 Not Found")

        result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        mock_helper.connector_logger.warning.assert_called_once()

    def test_request_data_invalid_json_returns_none(
        self, mock_helper, mock_config_api_key
    ):
        """request_data() returns None on JSON decode failure (e.g. HTML error page)."""
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.side_effect = ValueError("Expecting value")
        client.session.get.return_value = mock_resp

        with patch("teamt5_services.client.time.sleep"):
            result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        mock_helper.connector_logger.warning.assert_called_once()

    def test_request_data_calls_ensure_valid_token(
        self, mock_helper, mock_config_api_key
    ):
        """_ensure_valid_token() is called before each request."""
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.return_value = {}
        client.session.get.return_value = mock_resp

        with (
            patch.object(client, "_ensure_valid_token") as mock_ensure,
            patch("teamt5_services.client.time.sleep"),
        ):
            client.request_data("https://api.threatvision.org/test")

        mock_ensure.assert_called_once()
