import base64
from datetime import datetime, timezone

import requests
from email_client._http import get_with_retry, parse_json
from email_client.base import BaseEmailClient, EmailAttachment, EmailMessage
from google.auth.transport.requests import Request
from google.oauth2 import service_account


def _b64url(data: str) -> bytes:
    """Decode a Gmail base64url payload, tolerating missing '=' padding.

    Gmail message part bodies are base64url-encoded and frequently omit
    padding; ``base64.urlsafe_b64decode`` raises ``binascii.Error`` on such
    input, so re-pad to a multiple of 4 first.
    """
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class GmailClient(BaseEmailClient):
    """Gmail API email client."""

    BASE_URL = "https://gmail.googleapis.com/gmail/v1"
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    def __init__(
        self,
        credentials_file: str,
        user_id: str = "me",
        tls_verify: bool = True,
    ):
        self._credentials_file = credentials_file
        self._user_id = user_id
        self._tls_verify = tls_verify
        self._session: requests.Session | None = None
        self._credentials = None

    def connect(self) -> None:
        self._credentials = service_account.Credentials.from_service_account_file(
            self._credentials_file, scopes=self.SCOPES
        )
        if self._user_id != "me":
            self._credentials = self._credentials.with_subject(self._user_id)
        self._credentials.refresh(Request())
        self._session = requests.Session()
        self._session.verify = self._tls_verify
        self._session.headers["Authorization"] = f"Bearer {self._credentials.token}"

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def _refresh_if_needed(self) -> None:
        if self._credentials and self._credentials.expired:
            self._credentials.refresh(Request())
            self._session.headers["Authorization"] = f"Bearer {self._credentials.token}"

    def fetch_emails(
        self,
        sender: str,
        since: datetime | None = None,
        max_results: int = 50,
    ) -> list[EmailMessage]:
        if not self._session:
            raise RuntimeError("Not connected to Gmail API")

        self._refresh_if_needed()

        query_parts = [f"from:{sender}"]
        if since:
            epoch = int(since.timestamp())
            query_parts.append(f"after:{epoch}")

        url = f"{self.BASE_URL}/users/{self._user_id}/messages"
        query = " ".join(query_parts)

        # Gmail caps a single list page at 100 results and returns a
        # nextPageToken when more match; page through until we have collected
        # max_results message IDs (or run out) so max_results > 100 is honoured
        # instead of silently truncating to the first page.
        message_ids: list[str] = []
        page_token: str | None = None
        while len(message_ids) < max_results:
            params = {
                "q": query,
                "maxResults": min(max_results - len(message_ids), 100),
            }
            if page_token:
                params["pageToken"] = page_token
            resp = get_with_retry(self._session, url, params=params)
            resp.raise_for_status()
            data = parse_json(resp)
            page = data.get("messages", [])
            if not page:
                break
            message_ids.extend(item["id"] for item in page)
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        messages = []
        for message_id in message_ids[:max_results]:
            msg = self._fetch_full_message(message_id)
            if msg:
                messages.append(msg)

        return messages

    def _fetch_full_message(self, message_id: str) -> EmailMessage | None:
        url = (
            f"{self.BASE_URL}/users/{self._user_id}/messages/{message_id}"
            f"?format=full"
        )
        resp = get_with_retry(self._session, url)
        resp.raise_for_status()
        data = parse_json(resp)

        headers = {}
        for h in data.get("payload", {}).get("headers", []):
            headers[h["name"].lower()] = h["value"]

        subject = headers.get("subject", "")
        sender_raw = headers.get("from", "")
        # Extract email from "Name <email>" format
        sender_display = sender_raw
        if "<" in sender_raw and ">" in sender_raw:
            sender = sender_raw.split("<")[1].rstrip(">")
        else:
            sender = sender_raw
        to_raw = [r.strip() for r in headers.get("to", "").split(",") if r.strip()]
        cc_raw = [r.strip() for r in headers.get("cc", "").split(",") if r.strip()]
        all_raw = to_raw + cc_raw
        recipients = []
        recipients_display = list(all_raw)
        for r in all_raw:
            if "<" in r and ">" in r:
                recipients.append(r.split("<")[1].rstrip(">"))
            else:
                recipients.append(r)

        date_str = headers.get("date", "")
        try:
            from email.utils import parsedate_to_datetime

            date = parsedate_to_datetime(date_str)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
        except Exception:
            internal_ts = data.get("internalDate", "0")
            date = datetime.fromtimestamp(int(internal_ts) / 1000, tz=timezone.utc)

        in_reply_to = headers.get("in-reply-to", "")
        references_raw = headers.get("references", "")
        references = references_raw.split() if references_raw else []
        gmail_message_id = headers.get("message-id", message_id)

        thread_id = data.get("threadId", gmail_message_id)

        body_plain, body_html = self._extract_body(data.get("payload", {}))
        attachments = self._extract_attachments(data, message_id)

        return EmailMessage(
            message_id=gmail_message_id,
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

    def _extract_body(self, payload: dict) -> tuple[str, str]:
        body_plain = ""
        body_html = ""

        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data", "")

        if body_data and mime_type == "text/plain":
            body_plain = _b64url(body_data).decode("utf-8", errors="replace")
        elif body_data and mime_type == "text/html":
            body_html = _b64url(body_data).decode("utf-8", errors="replace")

        for part in payload.get("parts", []):
            p_plain, p_html = self._extract_body(part)
            if p_plain and not body_plain:
                body_plain = p_plain
            if p_html and not body_html:
                body_html = p_html

        return body_plain, body_html

    def _extract_attachments(
        self, data: dict, message_id: str
    ) -> list[EmailAttachment]:
        attachments = []
        payload = data.get("payload", {})
        self._collect_attachments(payload, message_id, attachments)
        return attachments

    def _collect_attachments(
        self, part: dict, message_id: str, attachments: list
    ) -> None:
        filename = part.get("filename", "")
        body = part.get("body", {})

        if filename and body.get("attachmentId"):
            content = self._download_attachment(message_id, body["attachmentId"])
            attachments.append(
                EmailAttachment(
                    filename=filename,
                    content_type=part.get("mimeType", "application/octet-stream"),
                    content=content,
                    size=len(content),
                )
            )

        for sub_part in part.get("parts", []):
            self._collect_attachments(sub_part, message_id, attachments)

    def _download_attachment(self, message_id: str, attachment_id: str) -> bytes:
        url = (
            f"{self.BASE_URL}/users/{self._user_id}/messages/"
            f"{message_id}/attachments/{attachment_id}"
        )
        resp = get_with_retry(self._session, url)
        resp.raise_for_status()
        data_b64 = parse_json(resp).get("data", "")
        return _b64url(data_b64)

    def get_thread_id(self, message: EmailMessage) -> str:
        return message.thread_id
