"""Unit tests for connector.converter_to_stix.

Note: ConverterToStix needs a `helper` and `config` only for storage on the
instance — it doesn't call them during the methods we test, so a SimpleNamespace
mock is sufficient.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

import pycti
import pytest

from connector.converter_to_stix import ConverterToStix
from email_client.base import EmailMessage


@pytest.fixture
def converter():
    helper = SimpleNamespace()
    config = SimpleNamespace()
    return ConverterToStix(helper=helper, config=config)


@pytest.fixture
def sample_email():
    return EmailMessage(
        message_id="<abc@example.com>",
        subject="Security Alert",
        sender="alerts@example.com",
        recipients=["soc@company.com"],
        date=datetime(2026, 4, 8, 12, 30, 0, tzinfo=timezone.utc),
        body_plain="body",
        body_html="<p>body</p>",
        thread_id="thread-1",
        sender_display="Alerts <alerts@example.com>",
        recipients_display=["SOC <soc@company.com>"],
    )


class TestIdentity:
    def test_identity_id_is_deterministic(self, converter):
        # Stable across instantiations: pycti.Identity.generate_id is deterministic
        c2 = ConverterToStix(helper=SimpleNamespace(), config=SimpleNamespace())
        assert converter.identity_id == c2.identity_id

    def test_identity_id_format(self, converter):
        assert converter.identity_id.startswith("identity--")

    def test_identity_id_uses_pycti_generator(self, converter):
        # Must be produced by the pycti generator (not a hand-rolled uuid5), so the
        # platform and other connectors converge on the same STIX id for this entity.
        expected = pycti.Identity.generate_id(
            name="Email Cases Importer", identity_class="system"
        )
        assert converter.identity_id == expected

    def test_connector_identity_object(self, converter):
        ident = converter.connector_identity
        assert ident.name == "Email Cases Importer"
        assert ident.identity_class == "system"


class TestFormatCaseDescription:
    def test_uses_display_name_when_available(self, converter, sample_email):
        out = converter.format_case_description(sample_email)
        assert "Alerts <alerts@example.com>" in out
        assert "Security Alert" in out
        assert "2026-04-08 12:30:00 UTC" in out

    def test_falls_back_to_sender_when_no_display(self, converter, sample_email):
        sample_email.sender_display = ""
        out = converter.format_case_description(sample_email)
        assert "alerts@example.com" in out


class TestFormatEmailContentBlock:
    def test_basic_block(self, converter, sample_email):
        html = converter.format_email_content_block(
            sample_email, body_text="hello", attachment_names=[]
        )
        assert "<h2>Security Alert</h2>" in html
        assert "Original" in html
        assert "<blockquote>hello</blockquote>" in html

    def test_reply_label(self, converter, sample_email):
        html = converter.format_email_content_block(
            sample_email, body_text="reply body", attachment_names=[], is_reply=True
        )
        assert "Reply" in html
        assert "Original" not in html

    def test_passwords_found_block_appears(self, converter, sample_email):
        html = converter.format_email_content_block(
            sample_email,
            body_text="b",
            attachment_names=[],
            passwords_found=2,
        )
        assert "2 password(s) extracted" in html

    def test_attachments_listed(self, converter, sample_email):
        html = converter.format_email_content_block(
            sample_email,
            body_text="b",
            attachment_names=["file1.zip", "file2.pdf"],
        )
        assert "file1.zip" in html
        assert "file2.pdf" in html
        assert "<strong>Attachments:</strong>" in html

    def test_html_escaping_of_subject(self, converter, sample_email):
        sample_email.subject = "<script>alert(1)</script>"
        html = converter.format_email_content_block(
            sample_email, body_text="b", attachment_names=[]
        )
        # Raw <script> tag must not appear — it should be escaped
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_escaping_of_body(self, converter, sample_email):
        html = converter.format_email_content_block(
            sample_email,
            body_text="<b>bold</b> & evil",
            attachment_names=[],
        )
        assert "<b>bold</b>" not in html
        assert "&lt;b&gt;bold&lt;/b&gt;" in html
        assert "&amp; evil" in html

    def test_newlines_in_body_become_br(self, converter, sample_email):
        html = converter.format_email_content_block(
            sample_email, body_text="line1\nline2", attachment_names=[]
        )
        assert "line1<br>line2" in html

    def test_no_recipients_shows_placeholder(self, converter, sample_email):
        sample_email.recipients = []
        sample_email.recipients_display = []
        html = converter.format_email_content_block(
            sample_email, body_text="b", attachment_names=[]
        )
        # ASCII placeholder (avoids UTF-8 double-encoding of a literal em dash
        # on the OpenCTI content write path)
        assert "(none)" in html
        assert "—" not in html

    def test_content_is_ascii_safe_for_unicode(self, converter, sample_email):
        # Unicode in subject/body must be emitted as numeric character
        # references so the OpenCTI content field (which double-encodes raw
        # non-ASCII on write) cannot corrupt it.
        sample_email.subject = "Alert café 北京"
        html = converter.format_email_content_block(
            sample_email, body_text="body café 北京", attachment_names=[]
        )
        assert html.isascii()  # pure ASCII on the wire
        assert "&#233;" in html  # é -> numeric character reference
        assert "café" not in html  # no raw non-ASCII left in the payload
