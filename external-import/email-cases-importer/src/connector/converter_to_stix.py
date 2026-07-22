import html

import pycti
import stix2

from email_client.base import EmailMessage


def _html_ascii(text: str) -> str:
    """HTML-escape ``text`` and encode every non-ASCII character as a numeric
    character reference, yielding a pure-ASCII payload.

    The OpenCTI case ``content`` field double-encodes raw non-ASCII bytes on
    write (a literal 'é' round-trips as 'Ã©'). Emitting '&#233;' instead keeps
    the wire payload ASCII while rendering identically in the Content tab, so
    unicode email subjects/bodies (e.g. Arabic, CJK, accented Latin) display
    correctly.
    """
    return html.escape(text).encode("ascii", "xmlcharrefreplace").decode("ascii")


class ConverterToStix:
    """Creates the connector identity and formats case content."""

    def __init__(self, helper, config):
        self._helper = helper
        self._config = config
        self._identity_id = self._create_connector_identity()

    def _create_connector_identity(self) -> str:
        identity = stix2.Identity(
            id=pycti.Identity.generate_id(
                name="Email Cases Importer", identity_class="system"
            ),
            name="Email Cases Importer",
            identity_class="system",
            allow_custom=True,
            custom_properties={"x_opencti_reliability": "A - Completely reliable"},
        )
        self._connector_identity = identity
        return identity.id

    def format_case_description(self, email_msg: EmailMessage) -> str:
        """Build a plain-text description for the IR case."""
        date_str = email_msg.date.strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"Incident Response Case\n\n"
            f"Sender: {email_msg.sender_display or email_msg.sender}\n"
            f"Subject: {email_msg.subject}\n"
            f"First received: {date_str}"
        )

    def format_email_content_block(
        self,
        email_msg: EmailMessage,
        body_text: str,
        attachment_names: list[str],
        is_reply: bool = False,
        passwords_found: int = 0,
    ) -> str:
        """Format a single email as an HTML block for the case Content tab."""
        date_str = email_msg.date.strftime("%Y-%m-%d %H:%M:%S UTC")
        sender = _html_ascii(email_msg.sender_display or email_msg.sender)
        recipients = _html_ascii(
            ", ".join(email_msg.recipients_display or email_msg.recipients)
            if (email_msg.recipients_display or email_msg.recipients)
            else "(none)"
        )

        label = "Reply" if is_reply else "Original"
        subject = _html_ascii(email_msg.subject)

        parts = [
            "<hr>",
            f"<h2>{subject}</h2>",
            f"<p>"
            f"<strong>Date:</strong> {date_str} &mdash; <em>{label}</em><br>"
            f"<strong>From:</strong> <code>{sender}</code><br>"
            f"<strong>To:</strong> {recipients}"
            f"</p>",
        ]

        if body_text:
            escaped_body = _html_ascii(body_text.strip()).replace("\n", "<br>")
            parts.append(f"<blockquote>{escaped_body}</blockquote>")

        if passwords_found > 0:
            parts.append(
                f"<blockquote><em>{passwords_found} password(s) extracted "
                f"from email body and used to decrypt attachments.</em></blockquote>"
            )

        if attachment_names:
            files_html = ", ".join(
                f"<code>{_html_ascii(n)}</code>" for n in attachment_names
            )
            parts.append(f"<p><strong>Attachments:</strong> {files_html}</p>")

        return "\n".join(parts)

    @property
    def identity_id(self) -> str:
        return self._identity_id

    @property
    def connector_identity(self):
        return self._connector_identity
