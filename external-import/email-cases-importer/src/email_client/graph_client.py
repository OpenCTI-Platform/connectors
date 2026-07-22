import base64
from datetime import datetime, timezone

import requests

from email_client._http import get_with_retry, parse_json
from email_client.base import BaseEmailClient, EmailAttachment, EmailMessage


class GraphClient(BaseEmailClient):
    """Microsoft Graph API email client for Office 365 / Exchange Online."""

    BASE_URL = "https://graph.microsoft.com/v1.0"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        user_id: str,
        tls_verify: bool = True,
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._user_id = user_id
        self._tls_verify = tls_verify
        self._session: requests.Session | None = None
        self._access_token: str = ""

    def connect(self) -> None:
        self._session = requests.Session()
        self._session.verify = self._tls_verify
        self._authenticate()

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def _authenticate(self) -> None:
        token_url = (
            f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        )
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        resp = self._session.post(token_url, data=data)
        resp.raise_for_status()
        self._access_token = parse_json(resp)["access_token"]
        self._session.headers["Authorization"] = f"Bearer {self._access_token}"

    def fetch_emails(
        self,
        sender: str,
        since: datetime | None = None,
        max_results: int = 50,
    ) -> list[EmailMessage]:
        if not self._session:
            raise RuntimeError("Not connected to Microsoft Graph")

        # Escape single quotes in sender to prevent OData injection
        safe_sender = sender.replace("'", "''")
        filter_parts = [f"from/emailAddress/address eq '{safe_sender}'"]
        if since:
            # Normalize to UTC before appending the 'Z' suffix so a non-UTC
            # offset doesn't shift the query window.
            iso_since = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_parts.append(f"receivedDateTime ge {iso_since}")

        params = {
            "$filter": " and ".join(filter_parts),
            "$select": (
                "id,subject,from,toRecipients,body,receivedDateTime,"
                "conversationId,internetMessageHeaders,internetMessageId,"
                "hasAttachments"
            ),
            "$orderby": "receivedDateTime desc",
            "$top": min(max_results, 50),
        }

        url = f"{self.BASE_URL}/users/{self._user_id}/mailFolders/inbox/messages"
        messages = []

        while url and len(messages) < max_results:
            resp = get_with_retry(self._session, url, params=params)
            if resp.status_code == 401:
                self._authenticate()
                resp = get_with_retry(self._session, url, params=params)
            resp.raise_for_status()
            data = parse_json(resp)

            for item in data.get("value", []):
                msg = self._parse_message(item)
                if msg:
                    messages.append(msg)

            url = data.get("@odata.nextLink")
            params = None  # nextLink already has params

        return messages[:max_results]

    def _parse_message(self, item: dict) -> EmailMessage | None:
        message_id = item.get("internetMessageId", item.get("id", ""))
        subject = item.get("subject", "")
        from_email = item.get("from", {}).get("emailAddress", {})
        sender = from_email.get("address", "")
        sender_name = from_email.get("name", "")
        sender_display = f"{sender_name} <{sender}>" if sender_name else sender

        def _parse_recipients(items: list[dict]) -> tuple[list[str], list[str]]:
            addrs, displays = [], []
            for r in items:
                ea = r.get("emailAddress", {})
                addr = ea.get("address", "")
                name = ea.get("name", "")
                if addr:
                    addrs.append(addr)
                    displays.append(f"{name} <{addr}>" if name else addr)
            return addrs, displays

        to_addrs, to_display = _parse_recipients(item.get("toRecipients", []))
        cc_addrs, cc_display = _parse_recipients(item.get("ccRecipients", []))
        recipients = to_addrs + cc_addrs
        recipients_display = to_display + cc_display

        received = item.get("receivedDateTime", "")
        if received:
            date = datetime.fromisoformat(received.replace("Z", "+00:00"))
        else:
            date = datetime.now(timezone.utc)

        body = item.get("body", {})
        body_content = body.get("content", "")
        body_type = body.get("contentType", "text")
        body_plain = body_content if body_type == "text" else ""
        body_html = body_content if body_type == "html" else ""

        # Extract headers
        in_reply_to = ""
        references = []
        for header in item.get("internetMessageHeaders", []):
            name = header.get("name", "").lower()
            value = header.get("value", "")
            if name == "in-reply-to":
                in_reply_to = value
            elif name == "references":
                references = value.split()

        thread_id = item.get("conversationId", message_id)

        attachments = []
        if item.get("hasAttachments"):
            attachments = self._fetch_attachments(item["id"])

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
            references=references,
            attachments=attachments,
        )

    def _fetch_attachments(self, message_id: str) -> list[EmailAttachment]:
        url = (
            f"{self.BASE_URL}/users/{self._user_id}/messages/"
            f"{message_id}/attachments"
        )
        resp = get_with_retry(self._session, url)
        resp.raise_for_status()

        attachments = []
        for att in parse_json(resp).get("value", []):
            if att.get("@odata.type") != "#microsoft.graph.fileAttachment":
                continue
            content_bytes = base64.b64decode(att.get("contentBytes", ""))
            attachments.append(
                EmailAttachment(
                    filename=att.get("name", "unknown"),
                    content_type=att.get("contentType", "application/octet-stream"),
                    content=content_bytes,
                    size=len(content_bytes),
                )
            )
        return attachments

    def get_thread_id(self, message: EmailMessage) -> str:
        return message.thread_id
