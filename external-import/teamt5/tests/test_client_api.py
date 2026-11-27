"""Unit tests for ``teamt5_services.client.Teamt5Client``.

The client supports two authentication paths:

* OAuth 2.0 client credentials (recommended) — the session's
  ``JWTClientCredentialAuth`` exchanges ``client_id`` / ``client_secret``
  for a Bearer token against ``<api_base_url>/oauth/token`` and refreshes
  it (see ``test_auth.py``); the client maps a failed exchange to the
  standardized error matching its cause.
* Static API key (deprecated, kept for backwards compatibility) —
  uses the configured token as-is.

When both are configured OAuth takes precedence. ``request_data``
returns the decoded JSON body on success and ``None`` on transport
errors / invalid JSON, so the connector run can degrade gracefully
instead of crashing.
"""

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
from requests.adapters import HTTPAdapter
from teamt5_services.adapters import RetryingAdapter
from teamt5_services.auth import JWTClientCredentialAuth, TokenRequestError
from teamt5_services.client import Teamt5Client, _request_error_class


def _http_error(status_code):
    """An ``HTTPError`` carrying a response with ``status_code``, as ``raise_for_status`` raises it."""
    return requests.HTTPError(
        f"{status_code} Error", response=Mock(status_code=status_code)
    )


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
            assert not isinstance(mock_session.auth, JWTClientCredentialAuth)


class TestInitOAuth:
    def test_init_oauth_sets_client_credentials_auth(
        self, mock_helper, mock_config_oauth
    ):
        """With client_id/client_secret, the session authenticates with a
        ``JWTClientCredentialAuth``, which requests no token before the first request.
        """
        with (
            patch("teamt5_services.auth.requests.post") as mock_post,
            patch("teamt5_services.client.requests.Session") as mock_session_cls,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            Teamt5Client(mock_helper, mock_config_oauth)

        auth = mock_session.auth
        assert isinstance(auth, JWTClientCredentialAuth)
        assert auth.token_url == "https://api.threatvision.org/oauth/token"
        assert (auth.client_id, auth.client_secret) == ("cid", "csecret")
        assert auth.leeway == Teamt5Client._TOKEN_EXPIRY_MARGIN_SEC
        mock_post.assert_not_called()
        mock_session.headers.update.assert_not_called()

    def test_oauth_takes_precedence_over_api_key(self, mock_helper, mock_config_both):
        """When both OAuth credentials and api_key are set, OAuth wins."""
        with patch("teamt5_services.client.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            Teamt5Client(mock_helper, mock_config_both)

        assert isinstance(mock_session.auth, JWTClientCredentialAuth)
        mock_session.headers.update.assert_not_called()


def _oauth_error(body):
    """An ``HTTPError`` for a 400 from the token endpoint, whose JSON body is ``body``,
    or whose body is not JSON when ``body`` is ``None``."""
    response = Mock(status_code=400)
    if body is None:
        response.json.side_effect = requests.exceptions.JSONDecodeError(
            "Expecting value", "<html>", 0
        )
    else:
        response.json.return_value = body
    return requests.HTTPError("400 Client Error", response=response)


def _token_request_error(cause):
    """The ``TokenRequestError`` the auth raises when its token request fails with ``cause``."""
    err = TokenRequestError(f"Failed to obtain a token: {cause}")
    err.__cause__ = cause
    return err


class TestTokenRequestFailures:
    """Pin the OAuth token-exchange error contract.

    When the session's auth fails to obtain a token, ``request_data`` records
    the standardized ``ProviderApiError`` matching the cause — transport errors,
    HTTP error responses, bodies that are not JSON, without ``access_token`` or
    with an invalid ``expires_in`` — and returns ``None``, like any failed
    request: the caller stops, and the run reports the error to OpenCTI with its
    code and criticity while it continues with the next handler.
    """

    def _make_client(self, mock_helper, mock_config_oauth, cause):
        with patch("teamt5_services.client.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.auth.token_url = "https://api.threatvision.org/oauth/token"
            mock_session.get.side_effect = _token_request_error(cause)
            mock_session_cls.return_value = mock_session
            client = Teamt5Client(mock_helper, mock_config_oauth)
        client.session = mock_session
        return client

    @pytest.mark.parametrize(
        ("cause", "expected"),
        [
            (requests.ConnectionError("dns down"), ProviderApiConnectionError),
            (requests.exceptions.ConnectTimeout("slow"), ProviderApiTimeoutError),
            (requests.exceptions.ReadTimeout("slow"), ProviderApiTimeoutError),
            (requests.exceptions.TooManyRedirects("loop"), ProviderApiUnknownError),
            # Rejected credentials are answered with a 400 as often as with a 401
            (_oauth_error({"error": "invalid_client"}), ProviderApiAuthenticationError),
            (_oauth_error({"error": "invalid_grant"}), ProviderApiAuthenticationError),
            (
                _oauth_error({"error": "unauthorized_client"}),
                ProviderApiAuthenticationError,
            ),
            # Any other 400 is not about the credentials
            (_oauth_error({"error": "invalid_request"}), ProviderApiUnknownError),
            (
                _oauth_error({"error": "unsupported_grant_type"}),
                ProviderApiUnknownError,
            ),
            (_oauth_error({"message": "bad request"}), ProviderApiUnknownError),
            (_oauth_error(["invalid_client"]), ProviderApiUnknownError),
            (_oauth_error(None), ProviderApiUnknownError),
            (_http_error(401), ProviderApiAuthenticationError),
            (_http_error(403), ProviderApiAuthorizationError),
            (_http_error(404), ProviderApiNotFoundError),
            (_http_error(429), ProviderApiRateLimitError),
            (_http_error(500), ProviderApiServerError),
            (_http_error(502), ProviderApiServerError),
            (_http_error(418), ProviderApiUnknownError),
            (requests.HTTPError("401"), ProviderApiUnknownError),  # no response
            (ValueError("Expecting value"), ProviderApiInvalidResponseError),
            (
                requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0),
                ProviderApiInvalidResponseError,
            ),
            (KeyError("access_token"), ProviderApiInvalidResponseError),
            (ValueError("Invalid expires_in: None"), ProviderApiInvalidResponseError),
        ],
    )
    def test_token_failure_records_matching_error(
        self, mock_helper, mock_config_oauth, empty_error_store, cause, expected
    ):
        client = self._make_client(mock_helper, mock_config_oauth, cause)

        assert client.request_data("https://api.threatvision.org/test") is None

        errors = empty_error_store.get_errors()
        assert [type(e) for e in errors] == [expected]
        assert str(errors[0]).startswith("Failed to obtain OAuth token")
        # The original exception is kept as the cause of the recorded error
        assert errors[0].__cause__ is cause
        mock_helper.connector_logger.error.assert_called_once()
        assert mock_helper.connector_logger.error.call_args.kwargs["meta"][
            "token_url"
        ] == ("https://api.threatvision.org/oauth/token")

    def test_token_failure_through_a_real_session(
        self, mock_helper, mock_config_oauth, empty_error_store
    ):
        """With the real session and auth, a rejected token request stops
        ``request_data`` before any API request is sent."""
        rejected = Mock()
        rejected.raise_for_status.side_effect = _http_error(401)
        with patch("teamt5_services.auth.requests.post", return_value=rejected):
            client = Teamt5Client(mock_helper, mock_config_oauth)
            with patch.object(client.session, "send") as send:
                assert client.request_data("https://api.threatvision.org/test") is None

        send.assert_not_called()
        assert [type(e) for e in empty_error_store.get_errors()] == [
            ProviderApiAuthenticationError
        ]

    def test_next_request_gets_a_token_after_a_failed_one(
        self, mock_helper, mock_config_oauth, empty_error_store
    ):
        """A failed token request does not stop later requests: the next one
        requests a token again, as the next handler of the run does."""
        rejected = Mock()
        rejected.raise_for_status.side_effect = _http_error(503)
        granted = Mock()
        granted.json.return_value = {"access_token": "tok", "expires_in": 3600}
        page = Mock(status_code=200)
        page.json.return_value = {"success": True}
        with patch(
            "teamt5_services.auth.requests.post", side_effect=[rejected, granted]
        ):
            client = Teamt5Client(mock_helper, mock_config_oauth)
            with patch.object(client.session, "send", return_value=page) as send:
                first = client.request_data("https://api.threatvision.org/reports")
                second = client.request_data("https://api.threatvision.org/ioc")

        assert first is None
        assert second == {"success": True}
        assert send.call_args.args[0].headers["Authorization"] == "Bearer tok"
        assert [type(e) for e in empty_error_store.get_errors()] == [
            ProviderApiServerError
        ]


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
        ("err", "code", "summary"),
        [
            (_http_error(401), "api.authentication", "HTTP 401"),
            (_http_error(403), "api.authorization", "HTTP 403"),
            (_http_error(404), "api.not_found", "HTTP 404"),
            (_http_error(429), "api.rate_limit", "HTTP 429"),
            (_http_error(500), "api.server", "HTTP 500"),
            (requests.exceptions.ReadTimeout("read"), "api.timeout", "ReadTimeout"),
            (
                requests.exceptions.ConnectionError("dns"),
                "api.connection",
                "ConnectionError",
            ),
            (
                requests.exceptions.TooManyRedirects("loop"),
                "api.unknown",
                "TooManyRedirects",
            ),
            (requests.HTTPError("401"), "api.unknown", "HTTPError"),  # no response
        ],
    )
    def test_request_data_records_failed_request(
        self, mock_helper, mock_config_api_key, empty_error_store, err, code, summary
    ):
        """A failed request is recorded once as the matching error, and None is returned.

        The recorded message has no URL; the log has a static message, with the URL
        and the full error in its ``meta``."""
        client = self._make_client(mock_helper, mock_config_api_key)
        client.session.get.side_effect = err

        result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        errors = empty_error_store.get_errors()
        assert [type(error).code for error in errors] == [code]
        assert str(errors[0]) == f"Failed request to the TeamT5 API: {summary}"
        # The original exception is kept as the cause of the recorded error
        assert errors[0].__cause__ is err
        mock_helper.connector_logger.warning.assert_called_once_with(
            "Failed request to the TeamT5 API",
            meta={"url": "https://api.threatvision.org/test", "error": str(err)},
        )

    def test_signed_url_stays_out_of_the_recorded_error(
        self, mock_helper, mock_config_api_key, empty_error_store
    ):
        signed_url = "https://downloads.example.org/bundle.json?signature=secret"
        client = self._make_client(mock_helper, mock_config_api_key)
        client.session.get.side_effect = requests.HTTPError(
            f"404 Client Error: Not Found for url: {signed_url}",
            response=Mock(status_code=404),
        )

        client.request_data(signed_url)

        assert "secret" not in str(empty_error_store.get_errors()[0])

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
        # ``Response.json`` raises requests' JSONDecodeError, a RequestException
        mock_resp.json.side_effect = requests.exceptions.JSONDecodeError(
            "Expecting value", "<html>", 0
        )
        client.session.get.return_value = mock_resp

        with patch("teamt5_services.client.time.sleep"):
            result = client.request_data("https://api.threatvision.org/test")

        assert result is None
        mock_helper.connector_logger.warning.assert_called_once()
        errors = empty_error_store.get_errors()
        assert [type(error).code for error in errors] == ["api.invalid_response"]
        assert str(errors[0]) == "Failed request to the TeamT5 API: JSONDecodeError"

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


LISTING_URL = "https://api.threatvision.org/api/v2/reports"


def _http_response(status_code, body=b'{"success": true}'):
    """A ``requests.Response`` as ``HTTPAdapter.send`` returns it."""
    response = requests.Response()
    response.status_code = status_code
    response._content = body
    response._content_consumed = True  # no raw connection to read or close
    response.encoding = "utf-8"
    response.url = LISTING_URL
    return response


class TestSessionRetries:
    """Every request of the session goes through a ``RetryingAdapter``, so
    ``request_data`` reports a failure only once its retries are exhausted."""

    @pytest.fixture
    def client(self, mock_helper, mock_config_api_key):
        return Teamt5Client(mock_helper, mock_config_api_key)

    @pytest.fixture(autouse=True)
    def no_sleep(self):
        with (
            patch("teamt5_services.adapters.time.sleep") as sleep,
            patch("teamt5_services.client.time.sleep"),
        ):
            yield sleep

    @pytest.mark.parametrize(
        "url",
        [
            f"{LISTING_URL}?offset=0&date%5Bfrom%5D=0",
            f"{LISTING_URL}/some-alias.stix",
            "https://downloads.example.org/bundle.json?sig=abc",
            "http://plain.example.org/bundle.json",
        ],
    )
    def test_adapter_serves_every_url(self, client, url):
        adapter = client.session.get_adapter(url)

        assert isinstance(adapter, RetryingAdapter)
        assert adapter.max_attempts == Teamt5Client._MAX_ATTEMPTS == 5
        assert adapter.backoff == Teamt5Client._RETRY_BACKOFF_SEC == 1

    def test_recovered_failure_returns_the_page_and_records_nothing(
        self, client, empty_error_store
    ):
        with patch.object(
            HTTPAdapter,
            "send",
            side_effect=[requests.exceptions.ReadTimeout("slow"), _http_response(200)],
        ) as send:
            payload = client.request_data(LISTING_URL, {"offset": 0}, throttle=True)

        assert payload == {"success": True}
        assert send.call_count == 2
        assert empty_error_store.get_errors() == []

    def test_exhausted_retries_return_none_and_record_the_last_error(
        self, client, empty_error_store
    ):
        with patch.object(
            HTTPAdapter,
            "send",
            side_effect=[_http_response(503, b"") for _ in range(5)],
        ) as send:
            payload = client.request_data(LISTING_URL, {"offset": 0}, throttle=True)

        assert payload is None
        assert send.call_count == 5
        assert [type(e).code for e in empty_error_store.get_errors()] == ["api.server"]

    def test_bundle_download_is_retried_too(self, client, empty_error_store):
        with patch.object(
            HTTPAdapter,
            "send",
            side_effect=[
                _http_response(503, b""),
                _http_response(200, b'{"objects": []}'),
            ],
        ) as send:
            payload = client.request_data(f"{LISTING_URL}/some-alias.stix")

        assert payload == {"objects": []}
        assert send.call_count == 2
        assert empty_error_store.get_errors() == []


class TestRequestDataBodyNotAnObject:
    """A body that is valid JSON but not an object is an invalid response, so
    ``None`` always means a failure ``request_data`` recorded."""

    @pytest.mark.parametrize("body", [None, [], ["a"], "text", 3])
    def test_returns_none_and_records_an_invalid_response(
        self, mock_helper, mock_config_api_key, empty_error_store, body
    ):
        with patch("teamt5_services.client.requests.Session"):
            client = Teamt5Client(mock_helper, mock_config_api_key)
        response = Mock()
        response.json.return_value = body
        client.session.get.return_value = response

        assert client.request_data("https://api.threatvision.org/test") is None
        errors = empty_error_store.get_errors()
        assert [type(e).code for e in errors] == ["api.invalid_response"]
        assert "not a JSON object" in str(errors[0])
