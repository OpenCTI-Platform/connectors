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

import pytest
import requests
from connectors_sdk import (
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)
from teamt5_services.client import Teamt5Client, _request_error_class


def _http_error(status_code):
    """An ``HTTPError`` carrying a response with ``status_code``, as ``raise_for_status`` raises it."""
    return requests.HTTPError(
        f"{status_code} Error", response=Mock(status_code=status_code)
    )


def _make_token_response(access_token="tok123", expires_in=3600):
    resp = Mock()
    resp.json.return_value = {
        "access_token": access_token,
        "expires_in": expires_in,
    }
    resp.raise_for_status = Mock()
    return resp


class TestRequestErrorClass:
    """Pin the mapping from a failed ``requests`` call to a standardized error."""

    @pytest.mark.parametrize(
        ("err", "expected"),
        [
            (_http_error(401), ProviderApiAuthenticationError),
            (_http_error(403), ProviderApiAuthorizationError),
            (_http_error(404), ProviderApiNotFoundError),
            (_http_error(429), ProviderApiRateLimitError),
            (_http_error(500), ProviderApiServerError),
            (_http_error(503), ProviderApiServerError),
            (_http_error(400), ProviderApiUnknownError),
            (requests.HTTPError("no response"), ProviderApiUnknownError),
            (requests.exceptions.ReadTimeout("read"), ProviderApiTimeoutError),
            # ConnectTimeout is also a ConnectionError: the timeout wins
            (requests.exceptions.ConnectTimeout("connect"), ProviderApiTimeoutError),
            (requests.exceptions.ConnectionError("dns"), ProviderApiConnectionError),
            (requests.exceptions.SSLError("bad cert"), ProviderApiConnectionError),
            (
                requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0),
                ProviderApiInvalidResponseError,
            ),
            (requests.exceptions.TooManyRedirects("loop"), ProviderApiUnknownError),
            (
                requests.exceptions.ChunkedEncodingError("truncated"),
                ProviderApiUnknownError,
            ),
        ],
    )
    def test_maps_request_failure_to_standard_error(self, err, expected):
        assert _request_error_class(err) is expected


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


class TestRefreshTokenFailures:
    """Pin the OAuth token-exchange error contract.

    ``_refresh_token`` MUST raise the standardized ``ProviderApiError``
    matching the cause of every failure mode of the token endpoint —
    transport errors (``RequestException``), HTTP error responses,
    malformed JSON bodies, and missing ``access_token`` in an
    otherwise-200 reply — so the run reports it to OpenCTI with its
    code and criticity. Each case also asserts the structured error
    log is emitted via ``connector_logger.error`` (matching the rest
    of this connector's logging shape).
    """

    @pytest.mark.parametrize(
        ("err", "expected"),
        [
            (requests.ConnectionError("dns down"), ProviderApiConnectionError),
            (requests.exceptions.ConnectTimeout("slow"), ProviderApiTimeoutError),
            (requests.exceptions.ReadTimeout("slow"), ProviderApiTimeoutError),
            (requests.exceptions.TooManyRedirects("loop"), ProviderApiUnknownError),
        ],
    )
    def test_refresh_token_raises_on_request_exception(
        self, mock_helper, mock_config_oauth, err, expected
    ):
        with (
            patch("teamt5_services.client.requests.post", side_effect=err),
            patch("teamt5_services.client.requests.Session"),
        ):
            with pytest.raises(expected, match="Failed to obtain OAuth token") as info:
                Teamt5Client(mock_helper, mock_config_oauth)

        assert info.value.__cause__ is err
        mock_helper.connector_logger.error.assert_called_once()

    @pytest.mark.parametrize(
        ("status_code", "expected"),
        [
            # invalid_client is answered with a 400 as often as with a 401
            (400, ProviderApiAuthenticationError),
            (401, ProviderApiAuthenticationError),
            (403, ProviderApiAuthorizationError),
            (404, ProviderApiNotFoundError),
            (429, ProviderApiRateLimitError),
            (500, ProviderApiServerError),
            (502, ProviderApiServerError),
            (418, ProviderApiUnknownError),
        ],
    )
    def test_refresh_token_raises_on_http_error(
        self, mock_helper, mock_config_oauth, status_code, expected
    ):
        bad_resp = Mock()
        bad_resp.raise_for_status.side_effect = _http_error(status_code)
        with (
            patch("teamt5_services.client.requests.post", return_value=bad_resp),
            patch("teamt5_services.client.requests.Session"),
        ):
            with pytest.raises(expected, match=str(status_code)):
                Teamt5Client(mock_helper, mock_config_oauth)

        mock_helper.connector_logger.error.assert_called_once()

    def test_refresh_token_http_error_without_response_is_unknown(
        self, mock_helper, mock_config_oauth
    ):
        bad_resp = Mock()
        bad_resp.raise_for_status.side_effect = requests.HTTPError("401")
        with (
            patch("teamt5_services.client.requests.post", return_value=bad_resp),
            patch("teamt5_services.client.requests.Session"),
        ):
            with pytest.raises(ProviderApiUnknownError, match="401"):
                Teamt5Client(mock_helper, mock_config_oauth)

    @pytest.mark.parametrize(
        "decode_error",
        [
            ValueError("Expecting value"),
            requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0),
        ],
    )
    def test_refresh_token_raises_on_invalid_json(
        self, mock_helper, mock_config_oauth, decode_error
    ):
        bad_resp = Mock()
        bad_resp.raise_for_status = Mock()
        bad_resp.json.side_effect = decode_error
        with (
            patch("teamt5_services.client.requests.post", return_value=bad_resp),
            patch("teamt5_services.client.requests.Session"),
        ):
            with pytest.raises(
                ProviderApiInvalidResponseError, match="Expecting value"
            ):
                Teamt5Client(mock_helper, mock_config_oauth)

        mock_helper.connector_logger.error.assert_called_once()

    def test_refresh_token_raises_on_missing_access_token(
        self, mock_helper, mock_config_oauth
    ):
        bad_resp = Mock()
        bad_resp.raise_for_status = Mock()
        bad_resp.json.return_value = {"expires_in": 3600}  # no access_token
        with (
            patch("teamt5_services.client.requests.post", return_value=bad_resp),
            patch("teamt5_services.client.requests.Session"),
        ):
            with pytest.raises(ProviderApiInvalidResponseError, match="access_token"):
                Teamt5Client(mock_helper, mock_config_oauth)

        mock_helper.connector_logger.error.assert_called_once()

    def test_refresh_token_raises_on_invalid_expires_in(
        self, mock_helper, mock_config_oauth
    ):
        bad_resp = Mock()
        bad_resp.raise_for_status = Mock()
        bad_resp.json.return_value = {"access_token": "tok", "expires_in": "soon"}
        with (
            patch("teamt5_services.client.requests.post", return_value=bad_resp),
            patch("teamt5_services.client.requests.Session"),
        ):
            with pytest.raises(ProviderApiInvalidResponseError, match="soon"):
                Teamt5Client(mock_helper, mock_config_oauth)


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

    def test_expired_token_refresh_failure_propagates_out_of_request_data(
        self, mock_helper, mock_config_oauth
    ):
        """A token refresh failing inside ``request_data`` is raised, not swallowed.

        ``_ensure_valid_token`` runs inside the ``try`` of ``request_data``, whose
        ``except`` clauses catch ``RequestException`` and ``ValueError``. No
        standardized API error is either, so the authentication failure stops the
        run instead of being turned into a ``None`` page.
        """
        client = self._make_oauth_client(mock_helper, mock_config_oauth)
        client._token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        bad_resp = Mock()
        bad_resp.raise_for_status.side_effect = _http_error(401)
        with patch("teamt5_services.client.requests.post", return_value=bad_resp):
            with pytest.raises(ProviderApiAuthenticationError):
                client.request_data("https://api.threatvision.org/test")

        client.session.get.assert_not_called()

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

    def test_request_data_success_records_nothing(
        self, mock_helper, mock_config_api_key, empty_error_store
    ):
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.return_value = {"success": True}
        client.session.get.return_value = mock_resp

        client.request_data("https://api.threatvision.org/test")

        assert empty_error_store.get_errors() == []

    def test_request_data_http_error_returns_none_and_logs(
        self, mock_helper, mock_config_api_key
    ):
        """request_data() returns None and logs on 4xx/5xx."""
        client = self._make_client(mock_helper, mock_config_api_key)

        client.session.get.side_effect = requests.HTTPError("404 Not Found")

        result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        mock_helper.connector_logger.warning.assert_called_once()

    @pytest.mark.parametrize(
        ("err", "code"),
        [
            (_http_error(401), "api.authentication"),
            (_http_error(403), "api.authorization"),
            (_http_error(404), "api.not_found"),
            (_http_error(429), "api.rate_limit"),
            (_http_error(500), "api.server"),
            (requests.exceptions.ReadTimeout("read"), "api.timeout"),
            (requests.exceptions.ConnectionError("dns"), "api.connection"),
            (requests.exceptions.TooManyRedirects("loop"), "api.unknown"),
        ],
    )
    def test_request_data_records_failed_request(
        self, mock_helper, mock_config_api_key, empty_error_store, err, code
    ):
        """A failed request is recorded once as the matching error, and None is returned."""
        client = self._make_client(mock_helper, mock_config_api_key)
        client.session.get.side_effect = err

        result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        errors = empty_error_store.get_errors()
        assert [type(error).code for error in errors] == [code]
        assert "https://api.threatvision.org/test" in str(errors[0])
        mock_helper.connector_logger.warning.assert_called_once_with(str(errors[0]))

    def test_request_data_records_requests_json_decode_error(
        self, mock_helper, mock_config_api_key, empty_error_store
    ):
        """``requests``' JSONDecodeError is a RequestException: S1 records it."""
        client = self._make_client(mock_helper, mock_config_api_key)

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.side_effect = requests.exceptions.JSONDecodeError(
            "Expecting value", "<html>", 0
        )
        client.session.get.return_value = mock_resp

        result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        assert [type(e).code for e in empty_error_store.get_errors()] == [
            "api.invalid_response"
        ]

    def test_request_data_invalid_json_returns_none(
        self, mock_helper, mock_config_api_key, empty_error_store
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
        errors = empty_error_store.get_errors()
        assert [type(error).code for error in errors] == ["api.invalid_response"]
        assert "Expecting value" in str(errors[0])

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

    @pytest.mark.parametrize(
        "exc",
        [
            requests.exceptions.SSLError("bad cert"),
            requests.exceptions.TooManyRedirects("loop"),
            requests.exceptions.ChunkedEncodingError("truncated"),
            requests.exceptions.ProxyError("no proxy"),
            requests.exceptions.ConnectionError("dns"),
            requests.exceptions.ConnectTimeout("timeout"),
            requests.exceptions.ReadTimeout("read"),
            requests.exceptions.HTTPError("500"),
        ],
    )
    def test_request_data_returns_none_on_any_request_exception(
        self, mock_helper, mock_config_api_key, exc
    ):
        """Every concrete ``requests`` exception subclass collapses to ``None``.

        Pins the broadened ``except requests.RequestException`` contract
        so the "transport errors return ``None``" guarantee covers every
        shape the previous narrow tuple let bubble up — including
        ``SSLError`` / ``TooManyRedirects`` / ``ChunkedEncodingError`` /
        ``ProxyError`` (which used to crash the run before the fix).
        """
        client = self._make_client(mock_helper, mock_config_api_key)
        client.session.get.side_effect = exc

        result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        mock_helper.connector_logger.warning.assert_called_once()
