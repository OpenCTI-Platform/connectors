import datetime
from typing import Generator

from base_connector.client import BaseClient
from email_intel_imap.config import ConnectorConfig
from imap_tools.mailbox import MailBox
from imap_tools.message import MailMessage
from imap_tools.query import AND


class ConnectorClient(BaseClient):
    config: ConnectorConfig

    def fetch_from_relative_import_start_date(
        self,
    ) -> Generator[MailMessage, None, None]:
        """
        Fetch emails received since a given date.

        Args:
            since_date (datetime.date): The date to fetch emails since.

        Yields:
            EmailMessage: Each parsed email message one by one.
        """
        with MailBox(host=self.config.email_intel_imap.host).login(  # type: ignore
            username=self.config.email_intel_imap.username,
            password=self.config.email_intel_imap.password,
        ) as mailbox:
            since_date = (
                datetime.date.today()
                - self.config.email_intel_imap.relative_import_start_date
            )
            yield from mailbox.fetch(AND(date_gte=since_date))
