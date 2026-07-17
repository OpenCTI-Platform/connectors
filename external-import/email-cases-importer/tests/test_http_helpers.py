"""Unit tests for email_client._http (parse_json + get_with_retry)."""

from unittest.mock import MagicMock

import pytest

import email_client._http as http_mod
from email_client._http import EmailClientHTTPError, get_with_retry, parse_json


def _resp(status=200, json_data=None, json_exc=None, headers=None, text=""):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    if json_exc is not None:
        r.json.side_effect = json_exc
    else:
        r.json.return_value = json_data
    return r


class TestParseJson:
    def test_returns_parsed_body(self):
        assert parse_json(_resp(json_data={"ok": True})) == {"ok": True}

    def test_non_json_body_raises_typed_error(self):
        resp = _resp(
            status=200,
            json_exc=ValueError("no json"),
            headers={"Content-Type": "text/html"},
            text="<html>blocked by proxy</html>",
        )
        with pytest.raises(EmailClientHTTPError) as exc:
            parse_json(resp)
        assert "text/html" in str(exc.value)
        assert "blocked by proxy" in str(exc.value)


class TestGetWithRetry:
    def test_returns_immediately_on_200(self):
        sess = MagicMock()
        sess.get.return_value = _resp(200)
        out = get_with_retry(sess, "http://x")
        assert out.status_code == 200
        sess.get.assert_called_once()

    def test_retries_on_429_then_succeeds(self, monkeypatch):
        slept = []
        monkeypatch.setattr(http_mod.time, "sleep", lambda s: slept.append(s))
        sess = MagicMock()
        sess.get.side_effect = [
            _resp(429, headers={"Retry-After": "1"}),
            _resp(200, json_data={}),
        ]
        out = get_with_retry(sess, "http://x")
        assert out.status_code == 200
        assert sess.get.call_count == 2
        assert slept == [1]

    def test_gives_up_after_max_retries(self, monkeypatch):
        monkeypatch.setattr(http_mod.time, "sleep", lambda s: None)
        sess = MagicMock()
        sess.get.return_value = _resp(429, headers={"Retry-After": "0"})
        out = get_with_retry(sess, "http://x", max_retries=2)
        assert out.status_code == 429
        assert sess.get.call_count == 3  # initial + 2 retries

    def test_bad_retry_after_uses_default(self, monkeypatch):
        slept = []
        monkeypatch.setattr(http_mod.time, "sleep", lambda s: slept.append(s))
        sess = MagicMock()
        sess.get.side_effect = [
            _resp(429, headers={"Retry-After": "not-a-number"}),
            _resp(200),
        ]
        get_with_retry(sess, "http://x")
        assert slept == [http_mod._DEFAULT_RETRY_WAIT]

    def test_retry_after_capped(self, monkeypatch):
        slept = []
        monkeypatch.setattr(http_mod.time, "sleep", lambda s: slept.append(s))
        sess = MagicMock()
        sess.get.side_effect = [
            _resp(429, headers={"Retry-After": "9999"}),
            _resp(200),
        ]
        get_with_retry(sess, "http://x")
        assert slept == [http_mod._MAX_RETRY_WAIT]
