"""Unit tests for email_client.ews_client.EwsClient parsing + lifecycle.

Filter-construction is covered in test_ews_filter.py. Here we exercise
_convert_item (item -> EmailMessage), connect()/disconnect() with exchangelib
patched, and get_thread_id.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("exchangelib")

from email_client.base import EmailMessage  # noqa: E402
from email_client.ews_client import EwsClient  # noqa: E402


def test_oauth2_auth_type_raises_not_implemented():
    # OAuth2 is accepted by config but not implemented — connect() must fail
    # fast with a clear error rather than silently using the default flow.
    client = EwsClient(
        server="https://ews.example.com",
        username="user@example.com",
        password="secret",
        auth_type="OAuth2",
    )
    with pytest.raises(NotImplementedError):
        client.connect()


def _mailbox(email_address, name=""):
    return SimpleNamespace(email_address=email_address, name=name)


class _Body:
    def __init__(self, text, body_type="Text"):
        self._text = text
        self.body_type = body_type

    def __str__(self):
        return self._text


def _item(**overrides):
    base = dict(
        message_id="<m1@x>",
        subject="Security Alert",
        sender=_mailbox("alerts@x.com", "Alerts"),
        to_recipients=[_mailbox("soc@company.com", "SOC")],
        cc_recipients=[_mailbox("cc@company.com")],
        datetime_received=datetime(2026, 4, 8, 12, 30, tzinfo=timezone.utc),
        body=_Body("plain body"),
        in_reply_to="<parent@x>",
        conversation_id=SimpleNamespace(id="conv-1"),
        has_attachments=False,
        attachments=[],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _client():
    return EwsClient(server="https://x/EWS", username="u@x.com", password="p")


class TestConvertItem:
    def test_basic_fields(self):
        msg = _client()._convert_item(_item())
        assert msg.message_id == "<m1@x>"
        assert msg.subject == "Security Alert"
        assert msg.sender == "alerts@x.com"
        assert msg.sender_display == "Alerts <alerts@x.com>"
        assert "soc@company.com" in msg.recipients
        assert "cc@company.com" in msg.recipients
        assert msg.body_plain == "plain body"
        assert msg.thread_id == "conv-1"
        assert msg.in_reply_to == "<parent@x>"

    def test_html_body(self):
        msg = _client()._convert_item(_item(body=_Body("<p>x</p>", "HTML")))
        assert msg.body_html
        assert msg.body_plain == ""

    def test_naive_datetime_made_aware(self):
        naive = datetime(2026, 4, 8, 12, 30)
        msg = _client()._convert_item(_item(datetime_received=naive))
        assert msg.date.tzinfo is not None

    def test_missing_date_defaults_now(self):
        msg = _client()._convert_item(_item(datetime_received=None))
        assert msg.date is not None

    def test_thread_id_falls_back_to_message_id(self):
        msg = _client()._convert_item(_item(conversation_id=None))
        assert msg.thread_id == "<m1@x>"

    def test_sender_none(self):
        msg = _client()._convert_item(_item(sender=None))
        assert msg.sender == ""


class TestLifecycle:
    def test_connect_with_server(self):
        c = _client()
        with (
            patch("exchangelib.Credentials"),
            patch("exchangelib.Configuration"),
            patch("exchangelib.Account") as account_cls,
            patch("exchangelib.DELEGATE"),
        ):
            c.connect()
            account_cls.assert_called_once()
            assert c._account is account_cls.return_value

    def test_connect_autodiscover_without_server(self):
        c = EwsClient(server="", username="u@x.com", password="p")
        with (
            patch("exchangelib.Credentials"),
            patch("exchangelib.Account") as account_cls,
            patch("exchangelib.DELEGATE"),
        ):
            c.connect()
            assert account_cls.call_args.kwargs["autodiscover"] is True

    def test_disconnect_closes_protocol(self):
        c = _client()
        proto = MagicMock()
        c._account = SimpleNamespace(protocol=proto)
        c.disconnect()
        proto.close.assert_called_once()
        assert c._account is None

    def test_fetch_raises_when_not_connected(self):
        with pytest.raises(RuntimeError):
            _client().fetch_emails(sender="a@b.com")

    def test_get_thread_id(self):
        m = EmailMessage(
            message_id="x",
            subject="s",
            sender="a@b",
            recipients=[],
            date=None,
            body_plain="",
            body_html="",
            thread_id="conv-z",
        )
        assert _client().get_thread_id(m) == "conv-z"
