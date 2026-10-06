import email
import email.header
import email.utils
import imaplib
import ssl
from datetime import datetime, timezone

from email_client.base import BaseEmailClient, EmailAttachment, EmailMessage


class ImapClient(BaseEmailClient):
    """IMAP4 email client implementation."""

    def __init__(
        self,
        host: str,
        port: int = 993,
        username: str = "",
        password: str = "",
        folder: str = "INBOX",
        use_ssl: bool = True,
        tls_verify: bool = True,
    ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._folder = folder
        self._use_ssl = use_ssl
        self._tls_verify = tls_verify
        self._connection: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

    def connect(self) -> None:
        if self._use_ssl:
            ctx = ssl.create_default_context()
            if not self._tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._connection = imaplib.IMAP4_SSL(
                self._host, self._port, ssl_context=ctx
            )
        else:
            self._connection = imaplib.IMAP4(self._host, self._port)
        self._connection.login(self._username, self._password)
        self._connection.select(self._folder)

    def disconnect(self) -> None:
        if self._connection:
            try:
                self._connection.close()
                self._connection.logout()
            except Exception:
                pass
            self._connection = None

    def fetch_emails(
        self,
        sender: str,
        since: datetime | None = None,
        max_results: int = 50,
    ) -> list[EmailMessage]:
        if not self._connection:
            raise RuntimeError("Not connected to IMAP server")

        criteria_parts = [f'FROM "{sender}"']
        if since:
            date_str = since.strftime("%d-%b-%Y")
            criteria_parts.append(f"SINCE {date_str}")

        search_criteria = "(" + " ".join(criteria_parts) + ")"
        _, data = self._connection.search(None, search_criteria)

        if not data or not data[0]:
            return []

        message_ids = data[0].split()
        # Limit results
        message_ids = message_ids[-max_results:]

        messages = []
        for mid in message_ids:
            _, msg_data = self._connection.fetch(mid, "(RFC822)")
            if not msg_data or not msg_data[0]:
                continue
            raw_email = msg_data[0][1]
            msg = self._parse_email(raw_email)
            if msg:
                messages.append(msg)

        return messages

    def get_thread_id(self, message: EmailMessage) -> str:
        # IMAP doesn't have native thread IDs — use Message-ID as base
        if message.in_reply_to:
            return message.in_reply_to
        if message.references:
            return message.references[0]
        return message.message_id

    def _parse_email(self, raw: bytes) -> EmailMessage | None:
        msg = email.message_from_bytes(raw)

        message_id = msg.get("Message-ID", "")
        subject = self._decode_header(msg.get("Subject", ""))
        sender_raw = msg.get("From", "")
        sender_name, sender_addr = email.utils.parseaddr(sender_raw)
        sender = sender_addr
        sender_display = (
            f"{self._decode_header(sender_name)} <{sender_addr}>"
            if sender_name
            else sender_addr
        )
        to_parsed = [email.utils.parseaddr(r) for r in (msg.get_all("To") or [])]
        cc_parsed = [email.utils.parseaddr(r) for r in (msg.get_all("Cc") or [])]
        all_parsed = to_parsed + cc_parsed
        recipients = [addr for _, addr in all_parsed if addr]
        recipients_display = [
            f"{self._decode_header(name)} <{addr}>" if name else addr
            for name, addr in all_parsed
            if addr
        ]
        # parsedate_to_datetime returns None (and on some Python versions
        # raises) for a missing/malformed Date header — fall back to "now"
        # rather than crashing the whole fetch cycle.
        try:
            date_tuple = email.utils.parsedate_to_datetime(msg.get("Date", ""))
        except (TypeError, ValueError):
            date_tuple = None
        if date_tuple is None:
            date_tuple = datetime.now(timezone.utc)
        elif date_tuple.tzinfo is None:
            date_tuple = date_tuple.replace(tzinfo=timezone.utc)
        in_reply_to = msg.get("In-Reply-To", "")
        references_raw = msg.get("References", "")
        references = references_raw.split() if references_raw else []

        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in disposition:
                    att = self._extract_attachment(part)
                    if att:
                        attachments.append(att)
                elif content_type == "text/plain" and not body_plain:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_plain = payload.decode(charset, errors="replace")
                elif content_type == "text/html" and not body_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_html = payload.decode(charset, errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                if msg.get_content_type() == "text/html":
                    body_html = payload.decode(charset, errors="replace")
                else:
                    body_plain = payload.decode(charset, errors="replace")

        raw_headers = {}
        for key in msg.keys():
            raw_headers[key] = msg[key]

        return EmailMessage(
            message_id=message_id,
            subject=subject,
            sender=sender,
            recipients=recipients,
            date=date_tuple,
            body_plain=body_plain,
            body_html=body_html,
            thread_id=message_id,
            sender_display=sender_display,
            recipients_display=recipients_display,
            in_reply_to=in_reply_to,
            references=references,
            attachments=attachments,
            raw_headers=raw_headers,
        )

    def _extract_attachment(self, part) -> EmailAttachment | None:
        filename = part.get_filename()
        if not filename:
            return None
        filename = self._decode_header(filename)
        content = part.get_payload(decode=True)
        if not content:
            return None
        return EmailAttachment(
            filename=filename,
            content_type=part.get_content_type(),
            content=content,
            size=len(content),
        )

    @staticmethod
    def _decode_header(value: str) -> str:
        if not value:
            return ""
        decoded_parts = email.header.decode_header(value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(part)
        return " ".join(result)
