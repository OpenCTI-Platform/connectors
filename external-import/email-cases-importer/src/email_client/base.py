from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class EmailAttachment:
    """Represents an email attachment."""

    filename: str
    content_type: str
    content: bytes
    size: int


@dataclass
class EmailMessage:
    """Normalized email message across all protocols."""

    message_id: str
    subject: str
    sender: str
    recipients: list[str]
    date: datetime
    body_plain: str
    body_html: str
    thread_id: str
    sender_display: str = ""
    recipients_display: list[str] = field(default_factory=list)
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)
    attachments: list[EmailAttachment] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)


class BaseEmailClient(ABC):
    """Abstract base class for email protocol clients."""

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the email server."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the email server."""

    @abstractmethod
    def fetch_emails(
        self,
        sender: str,
        since: datetime | None = None,
        max_results: int = 50,
    ) -> list[EmailMessage]:
        """Fetch emails from a specific sender, optionally since a given date."""

    @abstractmethod
    def get_thread_id(self, message: EmailMessage) -> str:
        """Extract or compute a thread identifier for the message."""

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
