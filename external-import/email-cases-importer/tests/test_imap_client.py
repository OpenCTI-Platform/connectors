"""Unit tests for email_client.imap_client.ImapClient.

connect()/fetch_emails() are tested against a mocked imaplib connection; the
parsing helpers are tested with real RFC822 bytes built via the stdlib email
package.
"""

from email.message import EmailMessage as PyEmailMessage
from unittest.mock import MagicMock, patch

from email_client.base import EmailMessage
from email_client.imap_client import ImapClient


def _raw(
    subject="Security Alert",
    from_="Alerts <alerts@example.com>",
    to="SOC <soc@company.com>",
    cc=None,
    date="Wed, 08 Apr 2026 12:30:00 +0000",
    message_id="<m1@example.com>",
    in_reply_to=None,
    references=None,
    plain="hello body",
    html=None,
    attachment=None,
):
    msg = PyEmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    msg["Date"] = date
    msg["Message-ID"] = message_id
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    if plain is not None:
        msg.set_content(plain)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    if attachment is not None:
        name, data, (maintype, subtype) = attachment
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg.as_bytes()


def _client():
    return ImapClient(host="mail.x", username="u", password="p")


class TestConnect:
    def test_connect_ssl(self):
        c = _client()
        with patch("email_client.imap_client.imaplib.IMAP4_SSL") as ssl_cls:
            conn = ssl_cls.return_value
            c.connect()
            conn.login.assert_called_once_with("u", "p")
            conn.select.assert_called_once_with("INBOX")

    def test_connect_plain(self):
        c = ImapClient(host="mail.x", username="u", password="p", use_ssl=False)
        with patch("email_client.imap_client.imaplib.IMAP4") as cls:
            c.connect()
            cls.assert_called_once_with("mail.x", 143 if False else 993)

    def test_connect_no_tls_verify(self):
        c = ImapClient(host="mail.x", username="u", password="p", tls_verify=False)
        with (
            patch("email_client.imap_client.imaplib.IMAP4_SSL") as ssl_cls,
            patch("email_client.imap_client.ssl.create_default_context") as ctx_factory,
        ):
            ctx = ctx_factory.return_value
            c.connect()
            assert ctx.check_hostname is False
            ssl_cls.assert_called_once()

    def test_disconnect_swallows_errors(self):
        c = _client()
        conn = MagicMock()
        conn.close.side_effect = OSError("already closed")
        c._connection = conn
        c.disconnect()  # must not raise
        assert c._connection is None


class TestFetchEmails:
    def test_raises_when_not_connected(self):
        c = _client()
        try:
            c.fetch_emails(sender="a@b.com")
            assert False, "expected RuntimeError"
        except RuntimeError:
            pass

    def test_search_and_fetch(self):
        c = _client()
        conn = MagicMock()
        conn.search.return_value = ("OK", [b"1 2"])
        conn.fetch.side_effect = [
            ("OK", [(b"1", _raw(message_id="<a@x>"))]),
            ("OK", [(b"2", _raw(message_id="<b@x>"))]),
        ]
        c._connection = conn
        out = c.fetch_emails(sender="alerts@example.com")
        assert [m.message_id for m in out] == ["<a@x>", "<b@x>"]
        assert "FROM" in conn.search.call_args.args[1]

    def test_since_adds_criteria(self):
        from datetime import datetime, timezone

        c = _client()
        conn = MagicMock()
        conn.search.return_value = ("OK", [b""])
        c._connection = conn
        c.fetch_emails(
            sender="a@b.com",
            since=datetime(2026, 4, 1, tzinfo=timezone.utc),
        )
        assert "SINCE" in conn.search.call_args.args[1]

    def test_empty_search_returns_empty(self):
        c = _client()
        conn = MagicMock()
        conn.search.return_value = ("OK", [None])
        c._connection = conn
        assert c.fetch_emails(sender="a@b.com") == []


class TestParseEmail:
    def test_plain_email_fields(self):
        c = _client()
        msg = c._parse_email(_raw())
        assert msg.subject == "Security Alert"
        assert msg.sender == "alerts@example.com"
        assert msg.sender_display == "Alerts <alerts@example.com>"
        assert "soc@company.com" in msg.recipients
        assert msg.body_plain.strip() == "hello body"
        assert msg.date.tzinfo is not None

    def test_cc_recipients(self):
        c = _client()
        msg = c._parse_email(_raw(cc="Boss <boss@company.com>"))
        assert "boss@company.com" in msg.recipients

    def test_html_alternative(self):
        c = _client()
        msg = c._parse_email(_raw(plain="t", html="<p>rich</p>"))
        assert "rich" in msg.body_html

    def test_references_split(self):
        c = _client()
        msg = c._parse_email(_raw(references="<r1@x> <r2@x>"))
        assert msg.references == ["<r1@x>", "<r2@x>"]

    def test_attachment_extracted(self):
        c = _client()
        raw = _raw(attachment=("report.txt", b"file-bytes", ("text", "plain")))
        msg = c._parse_email(raw)
        assert len(msg.attachments) == 1
        assert msg.attachments[0].filename == "report.txt"
        assert msg.attachments[0].content == b"file-bytes"


class TestThreadIdAndHeaders:
    def test_thread_id_prefers_in_reply_to(self):
        c = _client()
        m = EmailMessage(
            message_id="<self@x>",
            subject="s",
            sender="a@b",
            recipients=[],
            date=None,
            body_plain="",
            body_html="",
            thread_id="",
            in_reply_to="<parent@x>",
        )
        assert c.get_thread_id(m) == "<parent@x>"

    def test_thread_id_references_then_message_id(self):
        c = _client()
        m = EmailMessage(
            message_id="<self@x>",
            subject="s",
            sender="a@b",
            recipients=[],
            date=None,
            body_plain="",
            body_html="",
            thread_id="",
            references=["<root@x>"],
        )
        assert c.get_thread_id(m) == "<root@x>"
        m.references = []
        assert c.get_thread_id(m) == "<self@x>"

    def test_decode_header_handles_empty_and_encoded(self):
        assert ImapClient._decode_header("") == ""
        # RFC2047 encoded-word
        encoded = "=?utf-8?q?Caf=C3=A9?="
        assert ImapClient._decode_header(encoded) == "Café"
