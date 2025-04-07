import contextlib
import datetime
from types import TracebackType
from typing import Dict, Generator, Optional, Type

from base_connector.client import BaseClient
from email_intel.config import ConnectorConfig
from email_intel.models import EmailIntelMessage
from imapclient import IMAPClient
from imapclient.response_types import Envelope
from pycti import OpenCTIConnectorHelper


class Client(BaseClient):
    config: ConnectorConfig

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorConfig) -> None:
        """
        Initialize the ImapClient configuration.
        """
        super().__init__(helper, config)
        self.client = IMAPClient(
            host=config.email_intel.imap_host,
            port=config.email_intel.imap_port,
            ssl=config.email_intel.imap_ssl,
        )

    def __enter__(self) -> "Client":
        """
        Establish connection and login to the IMAP server.

        In order to use the client safely, it is recommended to use it as follows:
        ```python
        with ImapClient(helper, config) as client:
            # Your code here
        ```
        """
        self.client.login(
            username=self.config.email_intel.imap_username,
            password=self.config.email_intel.imap_password,
        )
        self.client.select_folder(folder=self.config.email_intel.imap_mailbox)
        return self

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Safely logout from the IMAP server."""
        with contextlib.suppress(Exception):
            self.client.logout()

    def _parse_email(
        self, uid: int, data: Dict[bytes, bytes]
    ) -> Optional[EmailIntelMessage]:
        """
        Parse a raw IMAP message into an EmailMessage object.
        """
        envelope: Envelope | None = data.get(b"ENVELOPE")
        raw_message = data.get(b"RFC822")

        if not envelope or not raw_message:
            return None

        subject = envelope.subject.decode() if envelope.subject else None
        from_address = None
        if envelope.from_:
            address = envelope.from_[0]
            mailbox = address.mailbox.decode()
            host = address.host.decode()
            from_address = f"{mailbox}@{host}"

        return EmailIntelMessage(
            uid=uid,
            subject=subject,
            from_address=from_address,
            raw_message=raw_message,
        )

    def fetch_since(
        self, since_date: datetime.date
    ) -> Generator[EmailIntelMessage, None, None]:
        """
        Fetch emails received since a given date.

        Args:
            since_date (datetime.date): The date to fetch emails since.

        Yields:
            EmailMessage: Each parsed email message one by one.
        """
        if uids := self.client.search(["SINCE", since_date]):
            messages = self.client.fetch(uids, ["ENVELOPE", "RFC822"])
            for uid, data in messages.items():
                if email := self._parse_email(uid, data):
                    yield email
