"""Unit tests for email_client.gmail_client.GmailClient.

The google-auth dependency is stubbed in conftest; connect() is tested by
patching the module-level `service_account`/`Request`, and the fetch/parse paths
run against a MagicMock session with canned Gmail API payloads.
"""

import base64
from unittest.mock import MagicMock, patch

import pytest

import email_client.gmail_client as gmail_mod
from email_client.gmail_client import GmailClient


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


def test_b64url_tolerates_missing_padding():
    # Gmail base64url payloads frequently omit '=' padding; _b64url must decode
    # them without raising binascii.Error.
    raw = b"hello world payload with length forcing padding"
    unpadded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert gmail_mod._b64url(unpadded) == raw


def _resp(json_data):
    r = MagicMock()
    r.json.return_value = json_data
    r.raise_for_status.return_value = None
    return r


def _client(user_id="me"):
    return GmailClient(credentials_file="/creds.json", user_id=user_id)


def _full_message(message_id="m1", thread_id="t1", with_attachment=False):
    payload = {
        "mimeType": "multipart/mixed",
        "headers": [
            {"name": "Subject", "value": "Security Alert"},
            {"name": "From", "value": "Alerts <alerts@x.com>"},
            {"name": "To", "value": "SOC <soc@company.com>, plain@company.com"},
            {"name": "Date", "value": "Wed, 08 Apr 2026 12:30:00 +0000"},
            {"name": "Message-ID", "value": "<msgid@x>"},
            {"name": "In-Reply-To", "value": "<parent@x>"},
            {"name": "References", "value": "<r1@x> <r2@x>"},
        ],
        "parts": [
            {"mimeType": "text/plain", "body": {"data": _b64("plain body")}},
            {"mimeType": "text/html", "body": {"data": _b64("<p>rich</p>")}},
        ],
    }
    if with_attachment:
        payload["parts"].append(
            {
                "filename": "report.txt",
                "mimeType": "text/plain",
                "body": {"attachmentId": "att-1"},
            }
        )
    return {
        "id": message_id,
        "threadId": thread_id,
        "payload": payload,
        "internalDate": "1000",
    }


class TestConnect:
    def test_connect_default_user(self):
        c = _client(user_id="me")
        creds = MagicMock()
        creds.token = "TOK"
        with (
            patch.object(gmail_mod, "service_account") as sa,
            patch.object(gmail_mod, "Request"),
            patch("email_client.gmail_client.requests.Session") as sess_cls,
        ):
            sa.Credentials.from_service_account_file.return_value = creds
            sess = sess_cls.return_value
            sess.headers = {}
            c.connect()
            creds.with_subject.assert_not_called()
            creds.refresh.assert_called_once()
            assert sess.headers["Authorization"] == "Bearer TOK"

    def test_connect_delegated_user(self):
        c = _client(user_id="boss@x.com")
        creds = MagicMock()
        creds.token = "TOK"
        creds.with_subject.return_value = creds
        with (
            patch.object(gmail_mod, "service_account") as sa,
            patch.object(gmail_mod, "Request"),
            patch("email_client.gmail_client.requests.Session") as sess_cls,
        ):
            sa.Credentials.from_service_account_file.return_value = creds
            sess_cls.return_value.headers = {}
            c.connect()
            creds.with_subject.assert_called_once_with("boss@x.com")

    def test_disconnect(self):
        c = _client()
        sess = MagicMock()
        c._session = sess
        c.disconnect()
        sess.close.assert_called_once()
        assert c._session is None

    def test_refresh_if_needed(self):
        c = _client()
        creds = MagicMock()
        creds.expired = True
        creds.token = "NEW"
        c._credentials = creds
        c._session = MagicMock()
        c._session.headers = {}
        with patch.object(gmail_mod, "Request"):
            c._refresh_if_needed()
        assert c._session.headers["Authorization"] == "Bearer NEW"


class TestFetchEmails:
    def test_raises_when_not_connected(self):
        with pytest.raises(RuntimeError):
            _client().fetch_emails(sender="a@b.com")

    def test_lists_then_fetches_full(self):
        c = _client()
        sess = MagicMock()
        list_resp = _resp({"messages": [{"id": "m1"}]})
        full_resp = _resp(_full_message())
        sess.get.side_effect = [list_resp, full_resp]
        c._session = sess
        c._credentials = MagicMock(expired=False)
        out = c.fetch_emails(sender="alerts@x.com")
        assert len(out) == 1
        m = out[0]
        assert m.subject == "Security Alert"
        assert m.sender == "alerts@x.com"
        assert m.body_plain == "plain body"
        assert m.body_html == "<p>rich</p>"
        assert m.in_reply_to == "<parent@x>"
        assert m.references == ["<r1@x>", "<r2@x>"]
        assert m.thread_id == "t1"
        assert "soc@company.com" in m.recipients
        assert "plain@company.com" in m.recipients

    def test_since_adds_after_clause(self):
        from datetime import datetime, timezone

        c = _client()
        sess = MagicMock()
        sess.get.return_value = _resp({"messages": []})
        c._session = sess
        c._credentials = MagicMock(expired=False)
        c.fetch_emails(
            sender="a@b.com", since=datetime(2026, 4, 1, tzinfo=timezone.utc)
        )
        params = sess.get.call_args.kwargs["params"]
        assert "after:" in params["q"]

    def test_empty_list(self):
        c = _client()
        sess = MagicMock()
        sess.get.return_value = _resp({})
        c._session = sess
        c._credentials = MagicMock(expired=False)
        assert c.fetch_emails(sender="a@b.com") == []


class TestAttachmentsAndBody:
    def test_attachment_downloaded(self):
        c = _client()
        sess = MagicMock()
        list_resp = _resp({"messages": [{"id": "m1"}]})
        full_resp = _resp(_full_message(with_attachment=True))
        download_resp = _resp({"data": _b64("file-data")})
        sess.get.side_effect = [list_resp, full_resp, download_resp]
        c._session = sess
        c._credentials = MagicMock(expired=False)
        out = c.fetch_emails(sender="a@b.com")
        assert len(out[0].attachments) == 1
        assert out[0].attachments[0].filename == "report.txt"
        assert out[0].attachments[0].content == b"file-data"

    def test_extract_body_direct_plain(self):
        c = _client()
        plain, html = c._extract_body(
            {"mimeType": "text/plain", "body": {"data": _b64("hello")}}
        )
        assert plain == "hello"
        assert html == ""

    def test_get_thread_id(self):
        from email_client.base import EmailMessage

        c = _client()
        m = EmailMessage(
            message_id="x",
            subject="s",
            sender="a@b",
            recipients=[],
            date=None,
            body_plain="",
            body_html="",
            thread_id="t-9",
        )
        assert c.get_thread_id(m) == "t-9"

    def test_sender_without_angle_brackets(self):
        c = _client()
        sess = MagicMock()
        msg = _full_message()
        for h in msg["payload"]["headers"]:
            if h["name"] == "From":
                h["value"] = "bare@x.com"
        sess.get.side_effect = [_resp({"messages": [{"id": "m1"}]}), _resp(msg)]
        c._session = sess
        c._credentials = MagicMock(expired=False)
        out = c.fetch_emails(sender="bare@x.com")
        assert out[0].sender == "bare@x.com"


class TestRobustness:
    def test_non_json_200_raises_typed_error(self):
        from email_client._http import EmailClientHTTPError

        c = _client()
        sess = MagicMock()
        bad = MagicMock()
        bad.status_code = 200
        bad.raise_for_status.return_value = None
        bad.json.side_effect = ValueError("no json")
        bad.headers = {"Content-Type": "text/html"}
        bad.text = "<html>WAF</html>"
        sess.get.return_value = bad
        c._session = sess
        c._credentials = MagicMock(expired=False)
        with pytest.raises(EmailClientHTTPError):
            c.fetch_emails(sender="a@b.com")

    def test_retries_on_429(self, monkeypatch):
        import email_client._http as http_mod

        monkeypatch.setattr(http_mod.time, "sleep", lambda s: None)
        c = _client()
        sess = MagicMock()
        throttled = _resp({})
        throttled.status_code = 429
        throttled.headers = {"Retry-After": "0"}
        ok = _resp({"messages": []})
        ok.status_code = 200
        sess.get.side_effect = [throttled, ok]
        c._session = sess
        c._credentials = MagicMock(expired=False)
        out = c.fetch_emails(sender="a@b.com")
        assert out == []
        assert sess.get.call_count == 2
