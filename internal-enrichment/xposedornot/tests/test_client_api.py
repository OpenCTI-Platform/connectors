# -*- coding: utf-8 -*-
"""Unit tests for the XposedOrNot API client.

Covers the free and Plus API paths, clean results (404 and empty 200),
rate limiting and error branches — all with a mocked HTTP session, no
real network call.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import patch
from urllib.parse import quote

import requests
from src.xposedornot.client_api import (  # noqa: E402
    XposedOrNotClient,
    retry_after_seconds,
)

from tests.conftest import make_helper

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


class FakeResp:
    def __init__(
        self, status_code=200, json_data=None, headers=None, text="", bad_json=False
    ):
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}
        self.text = text
        self._bad_json = bad_json

    @property
    def is_redirect(self):
        return (
            self.status_code in (301, 302, 303, 307, 308) and "Location" in self.headers
        )

    @property
    def is_permanent_redirect(self):
        return self.status_code in (301, 308) and "Location" in self.headers

    def json(self):
        if self._bad_json:
            raise ValueError("bad json")
        return self._json


def _client(api_key=None):
    helper = make_helper()
    return XposedOrNotClient(helper, api_key=api_key), helper


def test_free_path_url_and_normalisation():
    client, _ = _client()
    resp = FakeResp(200, _fixture("breach_analytics.json"))
    with patch.object(client.session, "get", return_value=resp) as mocked_get:
        result = client.lookup("test@example.com")
    mocked_get.assert_called_once_with(
        "https://api.xposedornot.com/v1/breach-analytics",
        params={"email": "test@example.com"},
        timeout=30,
        allow_redirects=False,
    )
    assert result["risk_label"] == "Critical" and result["risk_score"] == 100
    assert [b["name"] for b in result["breaches"]] == [
        "AlienStealerLogs",
        "ManchesterAirportsGroup",
    ]
    first = result["breaches"][0]
    assert first["records"] == 299646818
    assert first["password_risk"] == "plaintext"
    assert first["data_classes"] == ["Email addresses", "Passwords"]


def test_plus_path_used_when_key_set_and_email_is_url_encoded():
    client, _ = _client(api_key="SECRET")
    assert client.session.headers["x-api-key"] == "SECRET"
    resp = FakeResp(200, _fixture("plus_detailed.json"))
    with patch.object(client.session, "get", return_value=resp) as mocked_get:
        result = client.lookup("user+tag@example.com")
    mocked_get.assert_called_once_with(
        "https://plus-api.xposedornot.com/v3/check-email/user%2Btag%40example.com",
        params={"detailed": "true"},
        timeout=30,
        allow_redirects=False,
    )
    assert [b["name"] for b in result["breaches"]] == ["AlienStealerLogs"]


def test_clean_email_404_and_empty_200_both_return_empty_dict():
    client, _ = _client()
    with patch.object(client.session, "get", return_value=FakeResp(404)):
        assert client.lookup("clean@example.org") == {}
    live_clean = _fixture("breach_analytics_clean.json")
    with patch.object(client.session, "get", return_value=FakeResp(200, live_clean)):
        assert client.lookup("clean@example.org") == {}
    empty = {"ExposedBreaches": {"breaches_details": []}}
    with patch.object(client.session, "get", return_value=FakeResp(200, empty)):
        assert client.lookup("clean@example.org") == {}


def test_malformed_nested_payloads_never_raise():
    """Malformed nesting must honour the contract: a dict, {} or None, never a raise."""
    client, _ = _client()
    for payload in (
        {"ExposedBreaches": {"breaches_details": ["Yahoo"]}},
        {"ExposedBreaches": "oops"},
        {"ExposedBreaches": {"breaches_details": {"not": "a list"}}},
        {"ExposedBreaches": {"breaches_details": [None, 7]}},
    ):
        with patch.object(client.session, "get", return_value=FakeResp(200, payload)):
            assert client.lookup("test@example.com") == {}

    partial = {
        "ExposedBreaches": {"breaches_details": [{"breach": "A"}]},
        "BreachMetrics": "x",
    }
    with patch.object(client.session, "get", return_value=FakeResp(200, partial)):
        result = client.lookup("test@example.com")
    assert result["risk_score"] is None and result["risk_label"] is None
    assert [b["name"] for b in result["breaches"]] == ["A"]


def test_malformed_plus_payload_never_raises():
    client, _ = _client(api_key="SECRET")
    for payload in ({"breaches": ["x"]}, {"breaches": "nope"}, {"breaches": [None]}):
        with patch.object(client.session, "get", return_value=FakeResp(200, payload)):
            assert client.lookup("test@example.com") == {}


def test_rate_limit_retries_then_gives_up_without_final_sleep():
    client, helper = _client()
    resp_429 = FakeResp(429, headers={"Retry-After": "0"})
    with patch.object(client.session, "get", return_value=resp_429) as mocked_get:
        with patch("src.xposedornot.client_api.time.sleep") as mocked_sleep:
            assert client.lookup("test@example.com") is None
    assert mocked_get.call_count == 3
    assert mocked_sleep.call_count == 2
    assert all(call.args[0] >= 1 for call in mocked_sleep.call_args_list)
    assert helper.connector_logger.error.called
    warned = str(helper.connector_logger.warning.call_args)
    assert "keyless" in warned


def test_zero_or_past_retry_after_still_backs_off():
    client, _ = _client()
    from email.utils import format_datetime as _fmt

    past = _fmt(datetime.now(timezone.utc) - timedelta(hours=1), usegmt=True)
    for header in ("0", past):
        responses = [FakeResp(429, headers={"Retry-After": header}), FakeResp(404)]
        with patch.object(client.session, "get", side_effect=responses):
            with patch("src.xposedornot.client_api.time.sleep") as mocked_sleep:
                assert client.lookup("test@example.com") == {}
        assert mocked_sleep.call_args.args[0] >= 1


def test_rate_limit_message_tailored_for_plus_api():
    client, helper = _client(api_key="SECRET")
    resp_429 = FakeResp(429, headers={"Retry-After": "0"})
    with patch.object(client.session, "get", return_value=resp_429):
        with patch("src.xposedornot.client_api.time.sleep"):
            assert client.lookup("test@example.com") is None
    warned = str(helper.connector_logger.warning.call_args)
    assert "Plus API" in warned and "keyless" not in warned


def test_retry_after_parsing_supports_delta_seconds_and_http_date():
    assert retry_after_seconds("7") == 7
    assert retry_after_seconds(None) == 15
    assert retry_after_seconds("") == 15
    assert retry_after_seconds("soon") == 15
    future = datetime.now(timezone.utc) + timedelta(seconds=30)
    assert 28 <= retry_after_seconds(format_datetime(future, usegmt=True)) <= 31
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    assert retry_after_seconds(format_datetime(past, usegmt=True)) == 0


def test_rate_limit_honours_http_date_retry_after_and_caps_it():
    client, _ = _client()
    soon = datetime.now(timezone.utc) + timedelta(seconds=20)
    later = datetime.now(timezone.utc) + timedelta(minutes=10)
    responses = [
        FakeResp(429, headers={"Retry-After": format_datetime(soon, usegmt=True)}),
        FakeResp(429, headers={"Retry-After": format_datetime(later, usegmt=True)}),
        FakeResp(404),
    ]
    with patch.object(client.session, "get", side_effect=responses):
        with patch("src.xposedornot.client_api.time.sleep") as mocked_sleep:
            assert client.lookup("test@example.com") == {}
    first, second = [call.args[0] for call in mocked_sleep.call_args_list]
    assert 18 <= first <= 21
    assert second == 60


def test_rate_limit_recovers_after_backoff():
    client, _ = _client()
    responses = [FakeResp(429, headers={"Retry-After": "0"}), FakeResp(404)]
    with patch.object(client.session, "get", side_effect=responses):
        with patch("src.xposedornot.client_api.time.sleep"):
            assert client.lookup("test@example.com") == {}


def test_request_exception_is_logged_without_the_email():
    client, helper = _client(api_key="SECRET")
    import requests as _requests

    boom = _requests.ConnectionError(
        "HTTPSConnectionPool(host='plus-api.xposedornot.com'): Max retries exceeded"
        " with url: /v3/check-email/user%2Btag%40example.com (Caused by timeout)"
    )
    with patch.object(client.session, "get", side_effect=boom):
        assert client.lookup("user+tag@example.com") is None
    logged = str(helper.connector_logger.error.call_args)
    assert "user+tag@example.com" not in logged
    assert "user%2Btag%40example.com" not in logged
    assert "ConnectionError" in logged and "<redacted>" in logged


def test_non_object_json_payload_returns_none():
    client, helper = _client()
    for payload in ([], None, "text", 42):
        with patch.object(client.session, "get", return_value=FakeResp(200, payload)):
            assert client.lookup("test@example.com") is None
    assert helper.connector_logger.error.call_count == 4
    assert "payload type" in str(helper.connector_logger.error.call_args)


def test_redirects_are_refused_and_logged_without_the_email():
    client, helper = _client()
    for status in (301, 302, 307, 308):
        resp = FakeResp(
            status,
            headers={
                "Location": "http://api.xposedornot.com/v1/breach-analytics?email=test%40example.com"
            },
        )
        with patch.object(client.session, "get", return_value=resp) as mocked_get:
            assert client.lookup("test@example.com") is None
        assert mocked_get.call_args.kwargs["allow_redirects"] is False
    logged = str(helper.connector_logger.error.call_args)
    assert "redirect refused" in logged
    assert "test@example.com" not in logged and "test%40example.com" not in logged
    assert "<redacted>" in logged


def test_redaction_leaves_text_untouched_when_there_is_no_email():
    from src.xposedornot.client_api import redact

    assert redact("connection to api failed", "") == "connection to api failed"
    assert redact("", "a@b.test") == ""
    assert redact("hit a@b.test twice a@b.test", "a@b.test") == (
        "hit <redacted> twice <redacted>"
    )


def test_redirect_without_location_header_is_still_refused():
    client, helper = _client()
    with patch.object(client.session, "get", return_value=FakeResp(302)):
        assert client.lookup("test@example.com") is None
    logged = str(helper.connector_logger.error.call_args)
    assert "redirect refused" in logged


def test_api_key_is_redacted_from_every_logged_field():
    secret = "SuperSecretKey123"
    body = '{"error": "bad key %s for test@example.com"}' % secret
    client, helper = _client(api_key=secret)
    with patch.object(client.session, "get", return_value=FakeResp(500, text=body)):
        assert client.lookup("test@example.com") is None
    logged = str(helper.connector_logger.error.call_args)
    assert secret not in logged and "test@example.com" not in logged
    assert logged.count("<redacted>") >= 2

    client, helper = _client(api_key=secret)
    location = f"https://evil.test/?x-api-key={quote(secret, safe='')}"
    with patch.object(
        client.session,
        "get",
        return_value=FakeResp(302, headers={"Location": location}),
    ):
        assert client.lookup("test@example.com") is None
    assert secret not in str(helper.connector_logger.error.call_args)
    assert quote(secret, safe="") not in str(helper.connector_logger.error.call_args)

    client, helper = _client(api_key=secret)
    boom = requests.ConnectionError(f"auth failed with x-api-key={secret}")
    with patch.object(client.session, "get", side_effect=boom):
        assert client.lookup("test@example.com") is None
    assert secret not in str(helper.connector_logger.error.call_args)


def test_redaction_is_case_insensitive_about_percent_escapes():
    """A lowercase escape must not slip the address into the logs.

    `quote` emits only uppercase escapes, so a literal comparison missed the
    equally valid `user%2btag%40example.com` a server may answer with, and the
    address reached the log despite the redaction guarantee.
    """
    from urllib.parse import quote

    from src.xposedornot.client_api import redact

    email = "user+tag@example.com"
    encoded = quote(email, safe="")
    assert encoded == "user%2Btag%40example.com"
    for spelling in (encoded, encoded.lower(), encoded.upper(), email, email.upper()):
        assert (
            email.lower()
            not in redact(f"redirect to https://x/?email={spelling}", email).lower()
        )
        assert "%2b" not in redact(f"?email={spelling}", email).lower()


def test_redaction_drops_the_payload_when_any_encoding_still_reveals_it():
    """Targeted replacement only knows the spellings it was given.

    Any character may be percent-encoded, so a partially encoded address
    matches neither the raw nor the fully encoded form. The whole payload is
    dropped rather than logged when the secret is still legible decoded.
    """
    from src.xposedornot.client_api import redact

    email = "user+tag@example.com"
    for spelling in (
        "us%65r%2Btag%40example.com",
        "USER%2BTAG@EXAMPLE.COM",
        "user%2Btag@example.com",
    ):
        assert redact(f"body={spelling}", email) == "<redacted>"
    assert redact("k=%73ecret", "secret") == "<redacted>"
    assert redact("nothing sensitive here", email) == "nothing sensitive here"


def test_redaction_handles_several_secrets_and_blank_ones():
    from src.xposedornot.client_api import redact

    assert redact("a KEY b MAIL c", "MAIL", "KEY") == "a <redacted> b <redacted> c"
    assert redact("nothing here", None, "") == "nothing here"
    assert redact("", "KEY") == ""


def test_error_body_is_logged_redacted():
    client, helper = _client()
    body = '{"error": "lookup failed for test@example.com"}'
    with patch.object(client.session, "get", return_value=FakeResp(500, text=body)):
        assert client.lookup("test@example.com") is None
    logged = str(helper.connector_logger.error.call_args)
    assert "test@example.com" not in logged and "<redacted>" in logged


def test_server_error_and_bad_json_return_none():
    client, helper = _client()
    with patch.object(client.session, "get", return_value=FakeResp(500, text="boom")):
        assert client.lookup("test@example.com") is None
    with patch.object(client.session, "get", return_value=FakeResp(200, bad_json=True)):
        assert client.lookup("test@example.com") is None
    assert helper.connector_logger.error.call_count == 2


def test_plus_auth_errors_logged_without_key_leak():
    client, helper = _client(api_key="SECRET")
    with patch.object(client.session, "get", return_value=FakeResp(422)):
        assert client.lookup("test@example.com") is None
    logged = str(helper.connector_logger.error.call_args)
    assert "SECRET" not in logged and "Plus API" in logged


def test_keyless_auth_error_does_not_blame_a_missing_plus_key():
    client, helper = _client()
    with patch.object(client.session, "get", return_value=FakeResp(403)):
        assert client.lookup("test@example.com") is None
    logged = str(helper.connector_logger.error.call_args)
    assert "community API" in logged and "Plus" not in logged


def test_to_int_does_not_launder_values_the_score_check_rejects():
    """Coercion must not invent a number the API did not send.

    `int()` turns True into 1 and 3.7 into 3, so a value `usable_score`
    rejects outright arrived downstream already laundered into one it
    accepts. `int(float("inf"))` also raises OverflowError, which was not
    caught. A string spelling a whole number is still read, since that
    changes the notation and not the value.
    """
    from src.xposedornot.client_api import _to_int
    from src.xposedornot.connector import usable_score

    for laundered in (True, False, 3.7, 99.9, float("inf"), float("nan")):
        assert _to_int(laundered) is None, laundered

    assert _to_int("42") == 42
    assert _to_int(42) == 42
    assert _to_int(42.0) == 42
    assert _to_int("abc") is None
    assert _to_int(None) is None
    assert _to_int(10**400) == 10**400

    for raw in (True, False, 3.7, 99.9, 150, -5, "abc", None, float("inf")):
        coerced = _to_int(raw)
        assert usable_score(raw) is None
        assert usable_score(coerced) is None, (raw, coerced)


def test_a_multiply_encoded_secret_is_still_redacted():
    """One decode pass only peels one layer.

    `%2573ecret` decodes to `%73ecret`, not to the secret, so a value encoded
    twice read as already clean and survived into the logged field.
    """
    from urllib.parse import quote, unquote

    from src.xposedornot.client_api import redact

    def recoverable(text, secret, depth=12):
        current = text
        for _ in range(depth):
            if secret.casefold() in current.casefold():
                return True
            nxt = unquote(current)
            if nxt == current:
                return False
            current = nxt
        return False

    assert redact("k=%2573ecret", "secret") == "<redacted>"

    for secret in ("s p@c/al+secret", "user+tag@example.com"):
        spelling = secret
        for _ in range(10):
            assert not recoverable(redact("body=" + spelling, secret), secret), spelling
            spelling = quote(spelling, safe="")

    assert redact("nothing sensitive", "s p@c/al+secret") == "nothing sensitive"


def test_fully_decoded_settles_and_is_bounded():
    from src.xposedornot.client_api import MAX_DECODE_PASSES, fully_decoded

    assert fully_decoded("plain") == "plain"
    assert fully_decoded("%2573ecret") == "secret"
    assert fully_decoded("a%2520b") == "a b"
    assert MAX_DECODE_PASSES >= 10
    deep = "secret"
    from urllib.parse import quote

    for _ in range(8):
        deep = quote(deep, safe="")
    assert fully_decoded(deep) == "secret"
