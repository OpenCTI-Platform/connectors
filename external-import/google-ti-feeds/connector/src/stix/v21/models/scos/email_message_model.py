"""The module defines a model for an Email Message in STIX 2.1 format."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    EmailMessage,
    _STIXBase21,
)


class EmailMessageModel(BaseSCOModel):
    """Model representing an Email Message in STIX 2.1 format."""

    is_multipart: bool = Field(
        ..., description="True if the email contains multiple MIME parts."
    )
    date: datetime | None = Field(
        default=None, description="Date/time the email was sent."
    )
    content_type: str | None = Field(
        default=None, description="Value of the Content-Type header."
    )
    from_ref: str | None = Field(
        default=None,
        description="STIX ID of the 'From' sender (type: email-address).",
    )
    sender_ref: str | None = Field(
        default=None,
        description="STIX ID of the 'Sender' (transmitter agent).",
    )
    to_refs: list[str] | None = Field(
        default=None,
        description="STIX IDs of the To: recipients (type: email-address).",
    )
    cc_refs: list[str] | None = Field(
        default=None,
        description="STIX IDs of the CC: recipients (type: email-address).",
    )
    bcc_refs: list[str] | None = Field(
        default=None,
        description="STIX IDs of the BCC: recipients (type: email-address).",
    )
    message_id: str | None = Field(
        default=None, description="Message-ID header field value."
    )
    subject: str | None = Field(
        default=None, description="Subject of the email message."
    )
    received_lines: list[str] | None = Field(
        default=None, description="list of Received header fields (in order)."
    )
    additional_header_fields: dict[str, str] | None = Field(
        default=None,
        description="Other header fields (not explicitly modeled); keys preserved as case-sensitive field names.",
    )
    body: str | None = Field(
        default=None,
        description="Email body content (must NOT be used if is_multipart is true).",
    )
    body_multipart: list[dict[str, Any]] | None = Field(
        default=None,
        description="list of MIME parts for the body (must NOT be used if is_multipart is false).",
    )
    raw_email_ref: str | None = Field(
        default=None,
        description="Reference to the full raw email (type: artifact).",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return EmailMessage(**self.model_dump(exclude_none=True))
