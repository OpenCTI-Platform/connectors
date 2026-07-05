# -*- coding: utf-8 -*-
"""Unit tests for the OSINT Industries API client.

They cover the success path plus every error/retry branch of ``query`` with a
mocked HTTP session, so no real network call is made.
"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

if SDK_AVAILABLE:
    import requests
    from osint_industries.client_api import OsintIndustriesClient

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti not installed in this environment",
)


class FakeResp:
    """Minimal stand-in for a requests.Response."""

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
            raise ValueError("invalid json")
        return self._json


def make_client(monkeypatch, responses):
    """Return (client, helper) whose session.post yields ``responses`` in order.

    An entry that is an Exception instance is raised instead of returned.
    """
    helper = MagicMock()
    client = OsintIndustriesClient(helper, api_key="k", base_url="https://api.example")
    seq = iter(responses)

    def fake_post(url, json=None, timeout=None):
        item = next(seq)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr("osint_industries.client_api.time.sleep", lambda *_: None)
    return client, helper


@sdk_required
def test_selector_type_for():
    client = OsintIndustriesClient(MagicMock(), api_key="k")
    assert client.selector_type_for("Email-Addr") == "email"
    assert client.selector_type_for("Unknown-Type") is None


@sdk_required
def test_default_base_url():
    client = OsintIndustriesClient(MagicMock(), api_key="k")
    assert client.base_url == OsintIndustriesClient.DEFAULT_BASE_URL


@sdk_required
def test_query_success(monkeypatch):
    client, _ = make_client(
        monkeypatch, [FakeResp(200, json_data=[{"module": "okru"}])]
    )
    assert client.query("email", "a@b.com") == [{"module": "okru"}]


@sdk_required
def test_query_not_found_returns_empty(monkeypatch):
    client, _ = make_client(monkeypatch, [FakeResp(404)])
    assert client.query("email", "a@b.com") == []


@sdk_required
@pytest.mark.parametrize("code", [401, 402, 500])
def test_query_error_codes_return_none(monkeypatch, code):
    client, helper = make_client(monkeypatch, [FakeResp(code, text="boom")])
    assert client.query("email", "a@b.com") is None
    assert helper.connector_logger.error.called


@sdk_required
def test_query_request_exception_returns_none(monkeypatch):
    client, helper = make_client(monkeypatch, [requests.RequestException("net down")])
    assert client.query("email", "a@b.com") is None
    helper.connector_logger.error.assert_called()


@sdk_required
def test_query_invalid_json_returns_none(monkeypatch):
    client, _ = make_client(monkeypatch, [FakeResp(200, bad_json=True)])
    assert client.query("email", "a@b.com") is None


@sdk_required
def test_query_rate_limited_then_success(monkeypatch):
    client, helper = make_client(
        monkeypatch,
        [
            FakeResp(429, headers={"Retry-After": "1"}),
            FakeResp(200, json_data={"ok": True}),
        ],
    )
    assert client.query("email", "a@b.com") == {"ok": True}
    helper.connector_logger.warning.assert_called()


@sdk_required
def test_query_rate_limited_exhausts_retries(monkeypatch):
    client, _ = make_client(monkeypatch, [FakeResp(429) for _ in range(3)])
    assert client.query("email", "a@b.com") is None
