from datetime import datetime, timezone

from email_client.base import BaseEmailClient, EmailAttachment, EmailMessage


class EwsClient(BaseEmailClient):
    """Exchange Web Services (EWS) email client using exchangelib."""

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        auth_type: str = "NTLM",
        tls_verify: bool = True,
    ):
        self._server = server
        self._username = username
        self._password = password
        self._auth_type = auth_type
        self._tls_verify = tls_verify
        self._account = None

    def connect(self) -> None:
        if self._auth_type == "OAuth2":
            raise NotImplementedError(
                "EWS OAuth2 authentication is not implemented. Set "
                "EMAIL_CASES_EWS_AUTH_TYPE=NTLM (default), or use the "
                "microsoft_graph protocol for OAuth2-based Office 365 access."
            )

        from exchangelib import (
            DELEGATE,
            Account,
            Configuration,
            Credentials,
        )
        from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter

        if not self._tls_verify:
            BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

        credentials = Credentials(self._username, self._password)

        if self._server:
            config = Configuration(
                server=self._server,
                credentials=credentials,
            )
            self._account = Account(
                primary_smtp_address=self._username,
                config=config,
                autodiscover=False,
                access_type=DELEGATE,
            )
        else:
            self._account = Account(
                primary_smtp_address=self._username,
                credentials=credentials,
                autodiscover=True,
                access_type=DELEGATE,
            )

    def disconnect(self) -> None:
        if self._account and self._account.protocol:
            self._account.protocol.close()
        self._account = None

    def fetch_emails(
        self,
        sender: str,
        since: datetime | None = None,
        max_results: int = 50,
    ) -> list[EmailMessage]:
        if not self._account:
            raise RuntimeError("Not connected to Exchange server")

        # Message.sender is a single-valued Mailbox field — exchangelib does NOT
        # accept nested lookups (`sender__email_address`) or the legacy
        # `from_emailaddresses` path; both raise InvalidField. The supported form
        # is a Mailbox object compared by equality; email_address is sufficient.
        from exchangelib import Mailbox

        inbox = self._account.inbox
        qs = inbox.filter(sender=Mailbox(email_address=sender))

        if since:
            # exchangelib accepts tz-aware datetime directly; no EWSDateTime
            # coercion needed on 5.x.
            qs = qs.filter(datetime_received__gte=since.astimezone(timezone.utc))

        qs = qs.order_by("-datetime_received")[:max_results]

        messages = []
        for item in qs:
            msg = self._convert_item(item)
            if msg:
                messages.append(msg)

        return messages

    def _convert_item(self, item) -> EmailMessage | None:
        message_id = item.message_id or ""
        subject = item.subject or ""
        sender = ""
        sender_display = ""
        if item.sender:
            sender = item.sender.email_address or ""
            name = item.sender.name or ""
            sender_display = f"{name} <{sender}>" if name else sender

        recipients = []
        recipients_display = []
        for recip_list in (item.to_recipients, item.cc_recipients):
            if recip_list:
                for r in recip_list:
                    if r.email_address:
                        recipients.append(r.email_address)
                        name = r.name or ""
                        recipients_display.append(
                            f"{name} <{r.email_address}>" if name else r.email_address
                        )

        date = item.datetime_received
        if date and date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        elif not date:
            date = datetime.now(timezone.utc)

        body_plain = ""
        body_html = ""
        if item.body:
            if item.body.body_type == "HTML":
                body_html = item.body
            else:
                body_plain = str(item.body)

        in_reply_to = item.in_reply_to or ""
        thread_id = ""
        if item.conversation_id:
            thread_id = str(item.conversation_id.id)
        if not thread_id:
            thread_id = message_id

        attachments = []
        if item.has_attachments and item.attachments:
            for att in item.attachments:
                from exchangelib import FileAttachment

                if isinstance(att, FileAttachment) and att.content:
                    attachments.append(
                        EmailAttachment(
                            filename=att.name or "unknown",
                            content_type=att.content_type or "application/octet-stream",
                            content=att.content,
                            size=len(att.content),
                        )
                    )

        return EmailMessage(
            message_id=message_id,
            subject=subject,
            sender=sender,
            recipients=recipients,
            date=date,
            body_plain=body_plain,
            body_html=body_html,
            thread_id=thread_id,
            sender_display=sender_display,
            recipients_display=recipients_display,
            in_reply_to=in_reply_to,
            references=[],
            attachments=attachments,
        )

    def get_thread_id(self, message: EmailMessage) -> str:
        return message.thread_id
