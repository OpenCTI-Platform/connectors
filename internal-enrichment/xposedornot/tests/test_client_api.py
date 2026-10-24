from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import patch

import pytest
import requests
from src.xposedornot.client_api import (
    PLUS_BASE_URL,
    XposedOrNotClient,
    redact,
    retry_after_seconds,
    usable_score,
)
from src.xposedornot.errors import XposedOrNotError

from tests.conftest import EMAIL, fixture, make_helper


class FakeResp:
    def __init__(self, status, payload=None, headers=None, text=None):
        self.status_code = status
        self.headers = headers or {}
        self._payload = payload
        self.text = text if text is not None else str(payload)

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def make_client(*responses, api_key=None):
    client = XposedOrNotClient(make_helper(), api_key=api_key)
    client.session.get = _queue(list(responses))
    return client


def _queue(responses):
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    get.calls = calls
    return get


@pytest.mark.parametrize(
    "text, expected",
    [
        ("user@example.com failed", "<redacted> failed"),
        ("USER%40EXAMPLE.COM", "<redacted>"),
        ("user%2540example.com", "<redacted>"),
        ("nothing here", "nothing here"),
        ("", ""),
    ],
)
def test_redact_blanks_raw_encoded_and_nested_forms(text, expected):
    assert redact(text, "user@example.com") == expected


def test_redact_handles_overlapping_secrets_in_one_pass():
    key = "xon_user@example.com_9f3c"
    out = redact(f"key={key} mail=user@example.com", "user@example.com", key)
    assert key not in out and "user@example.com" not in out and "9f3c" not in out


def test_redact_without_secrets_returns_the_text():
    assert redact("a@b.c", None, "") == "a@b.c"


def test_retry_after_seconds():
    future = datetime.now(timezone.utc) + timedelta(seconds=30)
    assert retry_after_seconds("7") == 7
    assert 28 <= retry_after_seconds(format_datetime(future)) <= 31
    assert retry_after_seconds(format_datetime(future - timedelta(hours=1))) == 0
    assert retry_after_seconds("garbage") == 15
    assert retry_after_seconds(None, default=3) == 3


@pytest.mark.parametrize(
    "value, expected",
    [
        (100, 100),
        (0, 0),
        (42.0, 42),
        ("50", None),
        (101, None),
        (-1, None),
        (7.5, None),
        (True, None),
    ],
)
def test_usable_score(value, expected):
    assert usable_score(value) == expected


def test_community_response_is_normalised():
    client = make_client(FakeResp(200, fixture("breach_analytics.json")))
    result = client.lookup(EMAIL)
    url, kwargs = client.session.get.calls[0]
    assert url == "https://api.xposedornot.com/v1/breach-analytics"
    assert kwargs["params"] == {"email": EMAIL} and kwargs["allow_redirects"] is False
    assert len(result["breaches"]) == 2
    first = result["breaches"][0]
    assert first["name"] and first["details"] and isinstance(first["records"], int)
    assert first["data_classes"] and first["password_risk"]
    assert usable_score(result["risk_score"]) is not None and result["risk_label"]


def test_plus_response_is_normalised_without_a_score():
    client = make_client(FakeResp(200, fixture("plus_detailed.json")), api_key="k")
    result = client.lookup(EMAIL)
    url, kwargs = client.session.get.calls[0]
    assert url == f"{PLUS_BASE_URL}/v3/check-email/victim%40example.com"
    assert kwargs["params"] == {"detailed": "true"}
    assert client.session.headers["x-api-key"] == "k"
    assert result["breaches"][0]["details"]
    assert result["risk_score"] is None and result["risk_label"] is None


@pytest.mark.parametrize(
    "payload",
    [
        fixture("breach_analytics_clean.json"),
        {},
        {"ExposedBreaches": "junk"},
        {"breaches": [{}]},
    ],
)
def test_clean_or_empty_payloads_are_a_clean_result(payload):
    assert make_client(FakeResp(200, payload)).lookup(EMAIL) == {}
    assert make_client(FakeResp(200, payload), api_key="k").lookup(EMAIL) == {}


def test_404_is_a_clean_result():
    assert make_client(FakeResp(404, "nope")).lookup(EMAIL) == {}


def test_malformed_breach_entries_are_skipped():
    payload = {
        "ExposedBreaches": {
            "breaches_details": [
                None,
                {"breach": ""},
                {"breach": "Ok", "xposed_records": "12"},
            ]
        }
    }
    result = make_client(FakeResp(200, payload)).lookup(EMAIL)
    assert [b["name"] for b in result["breaches"]] == ["Ok"]
    assert result["breaches"][0]["records"] == 12


def test_rate_limit_is_retried_honouring_retry_after():
    client = make_client(
        FakeResp(429, headers={"Retry-After": "2"}),
        FakeResp(200, fixture("breach_analytics.json")),
    )
    with patch("src.xposedornot.client_api.time.sleep") as sleep:
        assert client.lookup(EMAIL)["breaches"]
    sleep.assert_called_once_with(2)


def test_exhausted_rate_limit_raises():
    client = make_client(
        *(FakeResp(429, headers={"Retry-After": "0"}) for _ in range(3))
    )
    with patch("src.xposedornot.client_api.time.sleep") as sleep:
        with pytest.raises(XposedOrNotError, match="still rate limited"):
            client.lookup(EMAIL)
    assert sleep.call_args_list == [((1,),), ((1,),)]


@pytest.mark.parametrize(
    "response, match",
    [
        (FakeResp(500, text=f"boom {EMAIL}"), "error response"),
        (
            FakeResp(302, headers={"Location": f"http://x/?e={EMAIL}"}),
            "redirect refused",
        ),
        (FakeResp(403, {}), "request rejected"),
        (FakeResp(200, ValueError("bad json")), "JSON payload"),
        (FakeResp(200, ["list"]), "JSON payload"),
        (requests.ConnectionError(f"dns failed for {EMAIL}"), "request failed"),
    ],
)
def test_failures_raise_and_log_without_the_email(response, match):
    client = make_client(response)
    with pytest.raises(XposedOrNotError, match=match):
        client.lookup(EMAIL)
    logged = str(client.helper.connector_logger.error.call_args)
    assert EMAIL not in logged


def test_rejected_request_names_the_key_only_when_one_is_set():
    client = make_client(FakeResp(401, {}), api_key="k")
    with pytest.raises(XposedOrNotError, match="check the API key"):
        client.lookup(EMAIL)


def test_raised_error_traceback_carries_no_request_context():
    import traceback

    client = make_client(requests.ConnectionError(f"dns failed for {EMAIL} key=k"))
    client.api_key = "k"
    try:
        client.lookup(EMAIL)
    except XposedOrNotError as error:
        rendered = "".join(traceback.format_exception(error))
        assert error.__context__ is None and error.__cause__ is None
        assert EMAIL not in rendered and "dns failed" not in rendered
    else:
        raise AssertionError("lookup did not raise")


def test_rendered_pycti_error_log_carries_no_traceback_or_secrets(caplog):
    from pycti.utils.opencti_logger import logger as pycti_logger

    client = make_client(requests.ConnectionError(f"dns failed for {EMAIL} key=k"))
    client.api_key = "k"
    client.helper.connector_logger = pycti_logger("ERROR", json_logging=False)(
        "xon-test"
    )
    with caplog.at_level("ERROR", logger="xon-test"):
        with pytest.raises(XposedOrNotError):
            client.lookup(EMAIL)
    assert caplog.records
    assert all(not r.exc_info or r.exc_info[0] is None for r in caplog.records)
    assert "Traceback" not in caplog.text
    assert EMAIL not in caplog.text and "key=k" not in caplog.text
