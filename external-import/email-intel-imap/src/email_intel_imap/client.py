import datetime
from typing import Generator

from base_connector import BaseClient
from imap_tools.mailbox import MailBox
from imap_tools.message import MailMessage
from imap_tools.query import AND


class ConnectorClient(BaseClient):
    host: str
    port: int
    username: str
    password: str
    mailbox: str

    def fetch_from_relative_import_start_date(
        self, since_date: datetime.date
    ) -> Generator[MailMessage, None, None]:
        """
        Retrieve email messages received since a given date.

        To understand the AND argument of the fetch method, refer to the imap-tools documentation:
        https://pypi.org/project/imap-tools/#search-criteria

        Args:
            since_date (datetime.date): The date from which to begin retrieving emails.
                Only messages received on or after this date will be yielded.

        Yields:
            MailMessage: A parsed email message object representing one received email.
        """
        with MailBox(host=self.host, port=self.port).login(  # type: ignore
            username=self.username,
            password=self.password,
            initial_folder=self.mailbox,
        ) as mailbox:
            yield from mailbox.fetch(criteria=AND(date_gte=since_date))
