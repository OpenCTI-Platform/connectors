# -*- coding: utf-8 -*-
"""Unit tests for the XposedOrNot API client.

Covers the free and Plus API paths, clean results (404 and empty 200),
rate limiting and error branches — all with a mocked HTTP session, no
real network call.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

from xposedornot.client_api import XposedOrNotClient  # noqa: E402

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

    def json(self):
        if self._bad_json:
            raise ValueError("bad json")
        return self._json


def _client(api_key=None):
    helper = MagicMock()
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
    )
    assert result["risk_label"] == "Critical" and result["risk_score"] == 100
    assert [b["name"] for b in result["breaches"]] == ["Sysco", "Yahoo"]
    sysco = result["breaches"][0]
    assert sysco["records"] == 2699339
    assert sysco["data_classes"] == ["Email addresses", "Names", "Phone numbers"]


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
    )
    assert [b["name"] for b in result["breaches"]] == ["Sysco"]


def test_clean_email_404_and_empty_200_both_return_empty_dict():
    client, _ = _client()
    with patch.object(client.session, "get", return_value=FakeResp(404)):
        assert client.lookup("clean@example.org") == {}
    empty = {"ExposedBreaches": {"breaches_details": []}}
    with patch.object(client.session, "get", return_value=FakeResp(200, empty)):
        assert client.lookup("clean@example.org") == {}


def test_rate_limit_retries_then_gives_up_without_final_sleep():
    client, helper = _client()
    resp_429 = FakeResp(429, headers={"Retry-After": "0"})
    with patch.object(client.session, "get", return_value=resp_429) as mocked_get:
        with patch("xposedornot.client_api.time.sleep") as mocked_sleep:
            assert client.lookup("test@example.com") is None
    assert mocked_get.call_count == 3
    # no sleep on the final attempt -- it would only delay the error
    assert mocked_sleep.call_count == 2
    assert helper.connector_logger.error.called
    warned = str(helper.connector_logger.warning.call_args)
    assert "keyless" in warned


def test_rate_limit_message_tailored_for_plus_api():
    client, helper = _client(api_key="SECRET")
    resp_429 = FakeResp(429, headers={"Retry-After": "0"})
    with patch.object(client.session, "get", return_value=resp_429):
        with patch("xposedornot.client_api.time.sleep"):
            assert client.lookup("test@example.com") is None
    warned = str(helper.connector_logger.warning.call_args)
    assert "Plus API" in warned and "keyless" not in warned


def test_rate_limit_recovers_after_backoff():
    client, _ = _client()
    responses = [FakeResp(429, headers={"Retry-After": "0"}), FakeResp(404)]
    with patch.object(client.session, "get", side_effect=responses):
        with patch("xposedornot.client_api.time.sleep"):
            assert client.lookup("test@example.com") == {}


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
    assert "SECRET" not in logged
