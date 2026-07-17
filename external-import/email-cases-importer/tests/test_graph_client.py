"""Unit tests for email_client.graph_client.GraphClient.

The requests.Session is replaced with a MagicMock; responses are canned dicts
mirroring the Microsoft Graph /messages and /attachments payloads.
"""

import base64
from unittest.mock import MagicMock, patch

import pytest

from email_client.graph_client import GraphClient


def _client():
    return GraphClient(
        tenant_id="t", client_id="c", client_secret="s", user_id="user@x.com"
    )


def _resp(json_data, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_data
    r.raise_for_status.return_value = None
    return r


def _message(message_id="AAA", conversation_id="conv-1", with_attachment=False):
    return {
        "id": message_id,
        "internetMessageId": f"<{message_id}@x>",
        "subject": "Security Alert",
        "from": {"emailAddress": {"name": "Alerts", "address": "alerts@x.com"}},
        "toRecipients": [
            {"emailAddress": {"name": "SOC", "address": "soc@company.com"}}
        ],
        "ccRecipients": [{"emailAddress": {"name": "", "address": "cc@company.com"}}],
        "receivedDateTime": "2026-04-08T12:30:00Z",
        "conversationId": conversation_id,
        "body": {"contentType": "html", "content": "<p>hi</p>"},
        "internetMessageHeaders": [
            {"name": "In-Reply-To", "value": "<parent@x>"},
            {"name": "References", "value": "<r1@x> <r2@x>"},
        ],
        "hasAttachments": with_attachment,
    }


class TestAuth:
    def test_connect_authenticates_and_sets_header(self):
        c = _client()
        with patch("email_client.graph_client.requests.Session") as sess_cls:
            sess = sess_cls.return_value
            sess.headers = {}
            sess.post.return_value = _resp({"access_token": "TOK"})
            c.connect()
            assert sess.headers["Authorization"] == "Bearer TOK"
            assert c._session is sess


class TestFetchEmails:
    def test_raises_when_not_connected(self):
        with pytest.raises(RuntimeError):
            _client().fetch_emails(sender="a@b.com")

    def test_fetches_and_parses_message(self):
        c = _client()
        sess = MagicMock()
        sess.get.return_value = _resp({"value": [_message()]})
        c._session = sess
        out = c.fetch_emails(sender="alerts@x.com")
        assert len(out) == 1
        m = out[0]
        assert m.subject == "Security Alert"
        assert m.sender == "alerts@x.com"
        assert m.sender_display == "Alerts <alerts@x.com>"
        assert "soc@company.com" in m.recipients
        assert "cc@company.com" in m.recipients
        assert m.body_html == "<p>hi</p>"
        assert m.in_reply_to == "<parent@x>"
        assert m.references == ["<r1@x>", "<r2@x>"]
        assert m.thread_id == "conv-1"

    def test_escapes_single_quotes_in_sender(self):
        c = _client()
        sess = MagicMock()
        sess.get.return_value = _resp({"value": []})
        c._session = sess
        c.fetch_emails(sender="o'brien@x.com")
        params = sess.get.call_args.kwargs["params"]
        assert "o''brien@x.com" in params["$filter"]

    def test_since_adds_received_filter(self):
        from datetime import datetime, timezone

        c = _client()
        sess = MagicMock()
        sess.get.return_value = _resp({"value": []})
        c._session = sess
        c.fetch_emails(
            sender="a@b.com",
            since=datetime(2026, 4, 1, tzinfo=timezone.utc),
        )
        params = sess.get.call_args.kwargs["params"]
        assert "receivedDateTime ge" in params["$filter"]

    def test_pagination_follows_next_link(self):
        c = _client()
        sess = MagicMock()
        page1 = _resp(
            {
                "value": [_message(message_id="A")],
                "@odata.nextLink": "https://graph/next",
            }
        )
        page2 = _resp({"value": [_message(message_id="B")]})
        sess.get.side_effect = [page1, page2]
        c._session = sess
        out = c.fetch_emails(sender="a@b.com", max_results=50)
        assert {m.message_id for m in out} == {"<A@x>", "<B@x>"}
        assert sess.get.call_count == 2

    def test_reauth_on_401(self):
        c = _client()
        sess = MagicMock()
        sess.headers = {}
        unauthorized = _resp({}, status=401)
        ok = _resp({"value": []})
        sess.get.side_effect = [unauthorized, ok]
        sess.post.return_value = _resp({"access_token": "TOK2"})
        c._session = sess
        c.fetch_emails(sender="a@b.com")
        sess.post.assert_called_once()  # re-authenticated


class TestAttachments:
    def test_fetch_attachments_filters_file_type(self):
        c = _client()
        sess = MagicMock()
        msg = _message(message_id="A", with_attachment=True)
        att_payload = {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "r.txt",
                    "contentType": "text/plain",
                    "contentBytes": base64.b64encode(b"data").decode(),
                },
                {"@odata.type": "#microsoft.graph.itemAttachment", "name": "skip"},
            ]
        }
        sess.get.side_effect = [_resp({"value": [msg]}), _resp(att_payload)]
        c._session = sess
        out = c.fetch_emails(sender="a@b.com")
        assert len(out[0].attachments) == 1
        assert out[0].attachments[0].filename == "r.txt"
        assert out[0].attachments[0].content == b"data"


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
        with pytest.raises(EmailClientHTTPError):
            c.fetch_emails(sender="a@b.com")

    def test_retries_on_429(self, monkeypatch):
        import email_client._http as http_mod

        monkeypatch.setattr(http_mod.time, "sleep", lambda s: None)
        c = _client()
        sess = MagicMock()
        throttled = _resp({}, status=429)
        throttled.headers = {"Retry-After": "0"}
        sess.get.side_effect = [throttled, _resp({"value": []})]
        c._session = sess
        out = c.fetch_emails(sender="a@b.com")
        assert out == []
        assert sess.get.call_count == 2


class TestMisc:
    def test_disconnect_closes_session(self):
        c = _client()
        sess = MagicMock()
        c._session = sess
        c.disconnect()
        sess.close.assert_called_once()
        assert c._session is None

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
            thread_id="conv-9",
        )
        assert c.get_thread_id(m) == "conv-9"

    def test_missing_received_date_defaults_to_now(self):
        c = _client()
        sess = MagicMock()
        msg = _message()
        del msg["receivedDateTime"]
        sess.get.return_value = _resp({"value": [msg]})
        c._session = sess
        out = c.fetch_emails(sender="a@b.com")
        assert out[0].date is not None
