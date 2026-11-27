"""Tests for SpamhausClient: JWT login, token reuse, single re-login, pagination."""

import logging
import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk import (
    ApiClientError,
    ApiNotFoundError,
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
)
from connectors_sdk.shared.spamhaus import SPAMHAUS_API_URL, SpamhausClient
from freezegun import freeze_time
from pydantic import SecretStr

NOW = 1_800_000_000  # fixed "current" epoch, in seconds
PASSWORD = "p4ssw0rd-do-not-leak"
USERNAME = "analyst@example.com"
TOKEN_1 = "jwt-token-one-do-not-leak"
TOKEN_2 = "jwt-token-two-do-not-leak"


def _response(status_code=200, json_data=None, json_error=False, headers=None):
    """Build a fake requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 400
    if json_error:
        resp.json.side_effect = ValueError("not json")
    else:
        resp.json.return_value = json_data
    resp.text = "" if json_data is None else str(json_data)
    resp.headers = {"Content-Type": "application/json", **(headers or {})}
    resp.content = resp.text.encode()
    return resp


def _login_ok(token=TOKEN_1, expires=NOW + 86400):
    return _response(200, {"code": 200, "token": token, "expires": expires})


def _page(items, next_cursor=None, path="/threatfox/v1/iocs"):
    meta = {"page_size": 100, "total_items": len(items)}
    if next_cursor:
        meta["next_cursor"] = next_cursor
        meta["next_page"] = f"{path}?after={next_cursor}"
    return _response(200, {"items": items, "meta": meta})


@pytest.fixture
def client():
    """A client with retries disabled."""
    return SpamhausClient(
        username=SecretStr(USERNAME),
        password=SecretStr(PASSWORD),
        connector_name="threatfox",
        connector_version="1.2.3",
        max_retries=0,
    )


def _calls(raw):
    """(method, path) of every request made through the patched transport."""
    return [(c.args[0], c.args[1]) for c in raw.call_args_list]


class TestInit:
    def test_defaults_to_the_spamhaus_host(self, client):
        assert SPAMHAUS_API_URL == "https://api.spamhaus.com"
        assert client._base_url == SPAMHAUS_API_URL

    def test_user_agent_is_explicit_on_the_session(self, client):
        assert client._session.headers["User-Agent"] == "OpenCTI-threatfox/1.2.3"

    def test_no_network_call_at_init(self):
        with patch.object(SpamhausClient, "_raw_request") as raw:
            SpamhausClient(
                username=SecretStr(USERNAME),
                password=SecretStr(PASSWORD),
                connector_name="threatfox",
                connector_version="1.2.3",
            )
        raw.assert_not_called()


@freeze_time("2027-01-15 08:00:00")
class TestLogin:
    def test_login_posts_credentials_with_the_abusech_realm(self, client):
        with patch.object(client, "_raw_request", return_value=_login_ok()) as raw:
            client.login()

        assert _calls(raw) == [("POST", "/v1/login")]
        assert raw.call_args.kwargs["json"] == {
            "username": USERNAME,
            "password": PASSWORD,
            "realm": "abusech",
        }
        # No bearer token on the login request itself
        assert "headers" not in raw.call_args.kwargs

    def test_token_is_sent_as_bearer(self, client):
        with patch.object(
            client, "_raw_request", side_effect=[_login_ok(), _page([])]
        ) as raw:
            client.get_json("/threatfox/v1/iocs")

        assert raw.call_args.kwargs["headers"] == {"Authorization": f"Bearer {TOKEN_1}"}

    @pytest.mark.parametrize("status", [400, 401, 403])
    def test_rejected_credentials(self, client, status):
        with patch.object(client, "_raw_request", return_value=_response(status)):
            with pytest.raises(ProviderApiAuthenticationError) as exc_info:
                client.login()

        assert "Spamhaus credentials" in str(exc_info.value)
        assert PASSWORD not in str(exc_info.value)

    @pytest.mark.parametrize(
        ("status", "error_class", "code"),
        [
            (429, ProviderApiRateLimitError, "api.rate_limit"),
            (500, ProviderApiServerError, "api.server"),
            (502, ProviderApiServerError, "api.server"),
            (503, ProviderApiServerError, "api.server"),
            (418, ProviderApiInvalidResponseError, "api.invalid_response"),
        ],
    )
    def test_login_failure_reports_the_matching_error(
        self, client, status, error_class, code
    ):
        with patch.object(client, "_raw_request", return_value=_response(status)):
            with pytest.raises(error_class) as exc_info:
                client.login()

        assert exc_info.value.code == code

    @pytest.mark.parametrize(
        ("error", "error_class", "code"),
        [
            (
                requests.exceptions.ConnectionError("boom"),
                ProviderApiConnectionError,
                "api.connection",
            ),
            (
                requests.exceptions.Timeout("slow"),
                ProviderApiTimeoutError,
                "api.timeout",
            ),
            (
                # A connect timeout is both a ConnectionError and a Timeout.
                requests.exceptions.ConnectTimeout("slow"),
                ProviderApiTimeoutError,
                "api.timeout",
            ),
        ],
    )
    def test_login_network_failure(self, client, error, error_class, code):
        with patch.object(client, "_raw_request", side_effect=error):
            with pytest.raises(error_class) as exc_info:
                client.login()

        assert exc_info.value.code == code

        assert exc_info.value.__cause__ is error
        assert PASSWORD not in str(exc_info.value)

    @pytest.mark.parametrize(
        "payload",
        [
            {"code": 200},
            {"code": 200, "token": "", "expires": NOW},
            {"code": 200, "token": TOKEN_1},
            {"code": 200, "token": TOKEN_1, "expires": "soon"},
            ["not", "an", "object"],
        ],
    )
    def test_login_with_unexpected_payload(self, client, payload):
        with patch.object(client, "_raw_request", return_value=_response(200, payload)):
            with pytest.raises(ProviderApiInvalidResponseError) as exc_info:
                client.login()

        assert TOKEN_1 not in str(exc_info.value)

    def test_login_with_non_json_body(self, client):
        with patch.object(
            client, "_raw_request", return_value=_response(200, json_error=True)
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                client.login()


@freeze_time("2027-01-15 08:00:00")
class TestLoginRetry:
    """urllib3 never retries a POST: the client replays the login once itself."""

    @pytest.fixture
    def retrying_client(self):
        return SpamhausClient(
            username=SecretStr(USERNAME),
            password=SecretStr(PASSWORD),
            connector_name="threatfox",
            connector_version="1.2.3",
            max_retries=3,
            backoff_factor=0.5,
        )

    @pytest.mark.parametrize(
        "first_failure",
        [
            _response(502),
            _response(503),
            requests.exceptions.ConnectionError("boom"),
            requests.exceptions.ReadTimeout("slow"),
        ],
    )
    def test_a_transient_failure_is_retried_once(self, retrying_client, first_failure):
        with (
            patch.object(
                retrying_client,
                "_raw_request",
                side_effect=[first_failure, _login_ok()],
            ) as raw,
            patch("connectors_sdk.shared.spamhaus.client.time.sleep") as sleep,
        ):
            retrying_client.login()

        assert _calls(raw) == [("POST", "/v1/login"), ("POST", "/v1/login")]
        sleep.assert_called_once_with(0.5)
        assert retrying_client._token.get_secret_value() == TOKEN_1

    def test_a_second_failure_is_reported_without_a_third_attempt(
        self, retrying_client
    ):
        with (
            patch.object(
                retrying_client,
                "_raw_request",
                side_effect=[_response(503), _response(503)],
            ) as raw,
            patch("connectors_sdk.shared.spamhaus.client.time.sleep"),
        ):
            with pytest.raises(ProviderApiServerError):
                retrying_client.login()

        assert len(_calls(raw)) == 2

    def test_two_network_failures_are_reported(self, retrying_client):
        error = requests.exceptions.ConnectionError("boom")
        with (
            patch.object(
                retrying_client, "_raw_request", side_effect=[error, error]
            ) as raw,
            patch("connectors_sdk.shared.spamhaus.client.time.sleep"),
        ):
            with pytest.raises(ProviderApiConnectionError):
                retrying_client.login()

        assert len(_calls(raw)) == 2

    @pytest.mark.parametrize("status", [400, 401, 403, 429])
    def test_a_refused_login_is_not_retried(self, retrying_client, status):
        with (
            patch.object(
                retrying_client, "_raw_request", return_value=_response(status)
            ) as raw,
            patch("connectors_sdk.shared.spamhaus.client.time.sleep") as sleep,
        ):
            with pytest.raises(
                (ProviderApiAuthenticationError, ProviderApiRateLimitError)
            ):
                retrying_client.login()

        assert len(_calls(raw)) == 1
        sleep.assert_not_called()

    def test_nothing_is_retried_when_retries_are_disabled(self, client):
        with patch.object(client, "_raw_request", return_value=_response(503)) as raw:
            with pytest.raises(ProviderApiServerError):
                client.login()

        assert len(_calls(raw)) == 1

    def test_the_retry_does_not_log_the_credentials(self, retrying_client, caplog):
        caplog.set_level(logging.DEBUG)
        with (
            patch.object(
                retrying_client,
                "_raw_request",
                side_effect=[_response(503), _login_ok()],
            ),
            patch("connectors_sdk.shared.spamhaus.client.time.sleep"),
        ):
            retrying_client.login()

        assert "trying once more" in caplog.text
        assert PASSWORD not in caplog.text
        assert TOKEN_1 not in caplog.text


@freeze_time("2027-01-15 08:00:00")
class TestMissingToken:
    def test_a_login_that_leaves_no_token_is_an_invalid_response(self, client):
        """The check must be a real exception: ``assert`` is stripped by ``python -O``."""
        with patch.object(client, "login"):
            with pytest.raises(
                ProviderApiInvalidResponseError, match="did not provide"
            ):
                client.get_json("/threatfox/v1/iocs")


class TestOrigin:
    """The bearer token must only ever go to the configured API origin."""

    @pytest.mark.parametrize(
        "path",
        [
            "https://another-host.example/resource",
            "http://api.spamhaus.com/threatfox/v1/iocs",
            "https://api.spamhaus.com.evil.example/x",
            "https://user@evil.example/x",
        ],
    )
    @pytest.mark.parametrize("call", ["get_json", "get_bytes", "paginate"])
    def test_a_foreign_absolute_url_is_refused_before_any_credential_is_sent(
        self, client, path, call
    ):
        with patch.object(client, "_raw_request") as raw:
            with pytest.raises(ValueError, match="relative to the API base URL"):
                result = getattr(client, call)(path)
                if call == "paginate":
                    list(result)

        raw.assert_not_called()

    @pytest.mark.parametrize(
        "path", ["/threatfox/v1/iocs", "threatfox/v1/iocs", "//threatfox/v1/iocs"]
    )
    def test_a_relative_path_is_still_accepted(self, client, path):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=int(time.time()) + 86400), _page([])],
        ):
            assert client.get_json(path)["items"] == []


class TestTokenReuse:
    def test_valid_token_is_reused(self, client):
        client._token_refresh_margin = 300
        expires = int(time.time()) + 86400
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=expires), _page([]), _page([])],
        ) as raw:
            client.get_json("/threatfox/v1/iocs")
            client.get_json("/threatfox/v1/iocs")

        assert _calls(raw).count(("POST", "/v1/login")) == 1

    def test_token_close_to_expiry_is_renewed(self, client):
        now = int(time.time())
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(TOKEN_1, expires=now + 100),  # inside the 300s margin
                _page([]),
                _login_ok(TOKEN_2, expires=now + 86400),
                _page([]),
            ],
        ) as raw:
            client.get_json("/threatfox/v1/iocs")
            client.get_json("/threatfox/v1/iocs")

        assert _calls(raw).count(("POST", "/v1/login")) == 2
        assert raw.call_args.kwargs["headers"] == {"Authorization": f"Bearer {TOKEN_2}"}


@freeze_time("2027-01-15 08:00:00")
class TestRequests:
    @staticmethod
    def _expires():
        return int(time.time()) + 86400

    def test_returns_parsed_json(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _page([{"id": 1}])],
        ) as raw:
            body = client.get_json("/threatfox/v1/iocs", params={"since": "x"})

        assert body["items"] == [{"id": 1}]
        assert raw.call_args.kwargs["params"] == {"since": "x"}

    def test_a_body_that_is_not_json_is_an_invalid_response(self, client):
        maintenance = _response(
            200,
            "<html>maintenance</html>",
            headers={"Content-Type": "text/html"},
        )
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), maintenance],
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                client.get_json("/threatfox/v1/iocs")

    def test_a_200_with_an_undecodable_json_body_is_an_invalid_response(self, client):
        broken = _response(200)
        broken.json.side_effect = requests.exceptions.JSONDecodeError(
            "Expecting value", "<html>", 0
        )
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), broken],
        ):
            with pytest.raises(ProviderApiInvalidResponseError) as excinfo:
                client.get_json("/threatfox/v1/iocs")

        assert "cannot be reached" not in str(excinfo.value)

    def test_single_relogin_on_401_then_retry(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(TOKEN_1, expires=self._expires()),
                _response(401, {"status": 401, "message": "expired"}),
                _login_ok(TOKEN_2, expires=self._expires()),
                _page([{"id": 7}]),
            ],
        ) as raw:
            body = client.get_json("/threatfox/v1/iocs")

        assert body["items"] == [{"id": 7}]
        assert _calls(raw) == [
            ("POST", "/v1/login"),
            ("GET", "/threatfox/v1/iocs"),
            ("POST", "/v1/login"),
            ("GET", "/threatfox/v1/iocs"),
        ]
        assert raw.call_args.kwargs["headers"] == {"Authorization": f"Bearer {TOKEN_2}"}

    def test_second_401_is_a_credentials_error_without_third_login(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _response(401),
                _login_ok(TOKEN_2, expires=self._expires()),
                _response(401),
            ],
        ) as raw:
            with pytest.raises(ProviderApiAuthenticationError) as exc_info:
                client.get_json("/threatfox/v1/iocs")

        assert _calls(raw).count(("POST", "/v1/login")) == 2
        assert "Spamhaus credentials" in str(exc_info.value)

    def test_relogin_failure_is_reported(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _response(401),
                _response(401),  # the login itself is now refused
            ],
        ):
            with pytest.raises(ProviderApiAuthenticationError):
                client.get_json("/threatfox/v1/iocs")

    def test_403_is_an_authorization_error(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(403)],
        ):
            with pytest.raises(ProviderApiAuthorizationError):
                client.get_json("/threatfox/v1/iocs")

    @pytest.mark.parametrize(
        ("status", "error_class", "code"),
        [
            (429, ProviderApiRateLimitError, "api.rate_limit"),
            (500, ProviderApiServerError, "api.server"),
            (503, ProviderApiServerError, "api.server"),
        ],
    )
    def test_throttling_and_server_errors_keep_their_own_code(
        self, client, status, error_class, code
    ):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(status)],
        ):
            with pytest.raises(error_class) as exc_info:
                client.get_json("/threatfox/v1/iocs")

        assert exc_info.value.code == code

    @pytest.mark.parametrize(
        ("error", "error_class", "code"),
        [
            (
                requests.exceptions.ConnectionError("boom"),
                ProviderApiConnectionError,
                "api.connection",
            ),
            (
                requests.exceptions.ReadTimeout("slow"),
                ProviderApiTimeoutError,
                "api.timeout",
            ),
            (
                # A connect timeout is both a ConnectionError and a Timeout.
                requests.exceptions.ConnectTimeout("slow"),
                ProviderApiTimeoutError,
                "api.timeout",
            ),
        ],
    )
    def test_network_errors_keep_their_own_code(self, client, error, error_class, code):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), error],
        ):
            with pytest.raises(error_class) as exc_info:
                client.get_json("/threatfox/v1/iocs")

        assert exc_info.value.code == code

    @pytest.mark.parametrize("status", [400, 404, 422])
    def test_other_client_errors_are_an_invalid_response(self, client, status):
        """A feed endpoint that rejects the request cannot be used: fall back."""
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(status)],
        ):
            with pytest.raises(ProviderApiInvalidResponseError) as exc_info:
                client.get_json("/threatfox/v1/iocs")

        assert exc_info.value.code == "api.invalid_response"
        assert f"HTTP {status}" in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, ApiClientError)


@freeze_time("2027-01-15 08:00:00")
class TestPaginate:
    @staticmethod
    def _expires():
        return int(time.time()) + 86400

    def test_follows_every_page(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _page([{"id": 1}, {"id": 2}], next_cursor="c1"),
                _page([{"id": 3}], next_cursor="c2"),
                _page([{"id": 4}]),
            ],
        ) as raw:
            pages = list(
                client.paginate(
                    "/threatfox/v1/iocs",
                    params={"since": "2027-01-01T00:00:00Z"},
                    page_size=2,
                )
            )

        assert pages == [[{"id": 1}, {"id": 2}], [{"id": 3}], [{"id": 4}]]
        get_params = [c.kwargs["params"] for c in raw.call_args_list[1:]]
        assert get_params == [
            {"since": "2027-01-01T00:00:00Z", "page_size": 2},
            {"since": "2027-01-01T00:00:00Z", "page_size": 2, "after": "c1"},
            {"since": "2027-01-01T00:00:00Z", "page_size": 2, "after": "c2"},
        ]

    def test_single_page(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _page([{"id": 1}])],
        ):
            assert list(client.paginate("/threatfox/v1/iocs")) == [[{"id": 1}]]

    def test_empty_result_yields_nothing(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _page([])],
        ):
            assert list(client.paginate("/threatfox/v1/iocs")) == []

    def test_cursor_is_read_from_next_page_when_next_cursor_is_missing(self, client):
        first = _response(
            200,
            {
                "items": [{"id": 1}],
                "meta": {"next_page": "/threatfox/v1/iocs?since=x&after=abc%3D"},
            },
        )
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), first, _page([{"id": 2}])],
        ) as raw:
            pages = list(client.paginate("/threatfox/v1/iocs"))

        assert pages == [[{"id": 1}], [{"id": 2}]]
        assert raw.call_args.kwargs["params"]["after"] == "abc="

    def test_a_cursor_that_does_not_advance_is_an_error(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _page([{"id": 1}], next_cursor="same"),
                _page([{"id": 1}], next_cursor="same"),
            ],
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                list(client.paginate("/threatfox/v1/iocs"))

    def test_next_page_without_a_cursor_is_an_error(self, client):
        broken = _response(
            200, {"items": [{"id": 1}], "meta": {"next_page": "/threatfox/v1/iocs"}}
        )
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), broken],
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                list(client.paginate("/threatfox/v1/iocs"))

    def test_a_rejected_page_request_is_an_invalid_response(self, client):
        """E.g. a `since` the API refuses: the pages cannot be read at all."""
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(400)],
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                list(client.paginate("/threatfox/v1/iocs", params={"since": "x"}))

    @pytest.mark.parametrize(
        "body", [["not", "an", "object"], {"meta": {}}, {"items": "x"}]
    )
    def test_unexpected_page_shape_is_an_error(self, client, body):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(200, body)],
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                list(client.paginate("/threatfox/v1/iocs"))

    @pytest.mark.parametrize(
        "meta",
        [
            [],
            "next",
            42,
            {"next_page": 42, "next_cursor": "c"},
            {"next_page": ["x"], "next_cursor": "c"},
            {"next_page": "/threatfox/v1/iocs?after=c", "next_cursor": {"bad": "c"}},
            {"next_page": "/threatfox/v1/iocs?after=c", "next_cursor": 7},
        ],
    )
    def test_malformed_pagination_metadata_is_an_invalid_response(self, client, meta):
        """It must map to a commercial error, so a connector can fall back on it."""
        broken = _response(200, {"items": [{"id": 1}], "meta": meta})
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), broken],
        ):
            with pytest.raises(ProviderApiInvalidResponseError):
                list(client.paginate("/threatfox/v1/iocs"))

    @pytest.mark.parametrize("meta", [None, {}, {"next_page": None}, {"next_page": ""}])
    def test_absent_or_empty_next_page_means_last_page(self, client, meta):
        page = _response(200, {"items": [{"id": 1}], "meta": meta})
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), page],
        ):
            assert list(client.paginate("/threatfox/v1/iocs")) == [[{"id": 1}]]

    def test_missing_meta_means_last_page(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _response(200, {"items": [{"id": 1}]}),
            ],
        ):
            assert list(client.paginate("/threatfox/v1/iocs")) == [[{"id": 1}]]


@freeze_time("2027-01-15 08:00:00")
class TestSecrets:
    def test_nothing_secret_is_logged(self, client, caplog):
        expires = int(time.time()) + 86400
        with caplog.at_level(logging.DEBUG):
            with patch.object(
                client,
                "_raw_request",
                side_effect=[
                    _login_ok(TOKEN_1, expires=expires),
                    _response(401),
                    _login_ok(TOKEN_2, expires=expires),
                    _page([]),
                ],
            ):
                client.get_json("/threatfox/v1/iocs")

        logged = caplog.text + "".join(str(r.__dict__) for r in caplog.records)
        for secret in (PASSWORD, TOKEN_1, TOKEN_2, USERNAME):
            assert secret not in logged

    def test_client_repr_does_not_show_secrets(self, client):
        client._token = SecretStr(TOKEN_1)
        text = repr(client) + str(vars(client))
        assert PASSWORD not in text
        assert TOKEN_1 not in text


@freeze_time("2027-01-15 08:00:00")
class TestGetBytes:
    @staticmethod
    def _expires():
        return int(time.time()) + 86400

    @staticmethod
    def _file(status=200, content=b"PK\x03\x04binary"):
        resp = _response(status, headers={"Content-Type": "application/zip"})
        resp.content = content
        return resp

    def test_returns_the_raw_body_with_the_bearer_token(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), self._file()],
        ) as raw:
            content = client.get_bytes("/urlhaus/v1/files/samples/abc")

        assert content == b"PK\x03\x04binary"
        assert raw.call_args.kwargs["headers"] == {"Authorization": f"Bearer {TOKEN_1}"}

    def test_reuses_the_token_of_json_calls(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _page([]),
                self._file(),
            ],
        ) as raw:
            client.get_json("/threatfox/v1/iocs")
            client.get_bytes("/urlhaus/v1/files/samples/abc")

        assert _calls(raw).count(("POST", "/v1/login")) == 1

    def test_single_relogin_on_401(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _response(401),
                _login_ok(TOKEN_2, expires=self._expires()),
                self._file(content=b"ok"),
            ],
        ) as raw:
            assert client.get_bytes("/urlhaus/v1/files/samples/abc") == b"ok"

        assert _calls(raw).count(("POST", "/v1/login")) == 2

    def test_second_401_is_a_credentials_error(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[
                _login_ok(expires=self._expires()),
                _response(401),
                _login_ok(TOKEN_2, expires=self._expires()),
                _response(401),
            ],
        ):
            with pytest.raises(ProviderApiAuthenticationError):
                client.get_bytes("/urlhaus/v1/files/samples/abc")

    def test_403_is_an_authorization_error(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(403)],
        ):
            with pytest.raises(ProviderApiAuthorizationError):
                client.get_bytes("/urlhaus/v1/files/samples/abc")

    def test_server_error_is_a_provider_server_error(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(503)],
        ):
            with pytest.raises(ProviderApiServerError):
                client.get_bytes("/urlhaus/v1/files/samples/abc")

    def test_404_propagates_as_is(self, client):
        with patch.object(
            client,
            "_raw_request",
            side_effect=[_login_ok(expires=self._expires()), _response(404)],
        ):
            with pytest.raises(ApiNotFoundError):
                client.get_bytes("/urlhaus/v1/files/samples/abc")
