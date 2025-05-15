"""The module defines a model for an Email Message in STIX 2.1 format."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import EmailMessage, _STIXBase21  # type: ignore


class EmailMessageModel(BaseSCOModel):
    """Model representing an Email Message in STIX 2.1 format."""

    is_multipart: bool = Field(
        ..., description="True if the email contains multiple MIME parts."
    )
    date: Optional[datetime] = Field(
        default=None, description="Date/time the email was sent."
    )
    content_type: Optional[str] = Field(
        default=None, description="Value of the Content-Type header."
    )
    from_ref: Optional[str] = Field(
        default=None,
        description="STIX ID of the 'From' sender (type: email-address).",
    )
    sender_ref: Optional[str] = Field(
        default=None,
        description="STIX ID of the 'Sender' (transmitter agent).",
    )
    to_refs: Optional[List[str]] = Field(
        default=None,
        description="STIX IDs of the To: recipients (type: email-address).",
    )
    cc_refs: Optional[List[str]] = Field(
        default=None,
        description="STIX IDs of the CC: recipients (type: email-address).",
    )
    bcc_refs: Optional[List[str]] = Field(
        default=None,
        description="STIX IDs of the BCC: recipients (type: email-address).",
    )
    message_id: Optional[str] = Field(
        default=None, description="Message-ID header field value."
    )
    subject: Optional[str] = Field(
        default=None, description="Subject of the email message."
    )
    received_lines: Optional[List[str]] = Field(
        default=None, description="List of Received header fields (in order)."
    )
    additional_header_fields: Optional[Dict[str, str]] = Field(
        default=None,
        description="Other header fields (not explicitly modeled); keys preserved as case-sensitive field names.",
    )
    body: Optional[str] = Field(
        default=None,
        description="Email body content (must NOT be used if is_multipart is true).",
    )
    body_multipart: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of MIME parts for the body (must NOT be used if is_multipart is false).",
    )
    raw_email_ref: Optional[str] = Field(
        default=None,
        description="Reference to the full raw email (type: artifact).",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return EmailMessage(**self.model_dump(exclude_none=True))


def test_email_message_model() -> None:
    """Test function to demonstrate the usage of EmailMessageModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Email Message ===
    minimal = EmailMessageModel(
        type="email-message",
        spec_version="2.1",
        id=f"email-message--{uuid4()}",
        is_multipart=False,
        subject="RE: Invoice Update",
        body="Please find attached the updated invoice for this quarter.",
    )

    print("=== MINIMAL EMAIL MESSAGE ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Email Message ===
    full = EmailMessageModel(
        type="email-message",
        spec_version="2.1",
        id=f"email-message--{uuid4()}",
        is_multipart=True,
        date=now,
        content_type="multipart/mixed",
        from_ref=f"email-addr--{uuid4()}",
        sender_ref=f"email-addr--{uuid4()}",
        to_refs=[f"email-addr--{uuid4()}", f"email-addr--{uuid4()}"],
        cc_refs=[f"email-addr--{uuid4()}"],
        bcc_refs=[f"email-addr--{uuid4()}"],
        message_id="<CA53Yd3Kz8zRq@example.com>",
        subject="URGENT: Credential Reset Required",
        received_lines=[
            "from mail.fakecorp.org by smtp.internal (Postfix) with ESMTP id A1BC12345;",
            "from relay01.net (relay01.net [10.10.10.5]) by edge.fakecorp.org with ESMTP;",
        ],
        additional_header_fields={
            "X-Originating-IP": "203.0.113.5",
            "X-Mailer": "Thunderbird 91.0",
        },
        body_multipart=[
            {
                "content_type": "text/plain",
                "content_disposition": "inline",
                "body": "Please verify your login to avoid suspension.",
            },
            {
                "content_type": "application/zip",
                "content_disposition": 'attachment; filename="invoice.zip"',
                "body_raw_ref": f"artifact--{uuid4()}",
            },
        ],
        raw_email_ref=f"artifact--{uuid4()}",
    )

    print("\n=== FULL EMAIL MESSAGE ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_email_message_model()
