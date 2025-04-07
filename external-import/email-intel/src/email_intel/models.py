from pydantic import BaseModel


class EmailIntelMessage(BaseModel):
    """
    Pydantic model representing a simplified email message fetched via IMAP.

    Attributes:
        uid (int): Unique identifier for the email message.
        subject (str | None): Subject of the email.
        from_address (str | None): Sender's email address.
        raw_message (bytes): Raw email message in bytes.
    """

    uid: int
    subject: str | None
    from_address: str | None
    raw_message: bytes
