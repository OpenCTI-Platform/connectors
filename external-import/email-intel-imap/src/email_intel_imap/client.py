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
        Fetch emails received since a given date.

        Args:
            since_date (datetime.date): The date to fetch emails since.

        Yields:
            EmailMessage: Each parsed email message one by one.
        """
        with MailBox(host=self.host, port=self.port).login(  # type: ignore
            username=self.username,
            password=self.password,
            initial_folder=self.mailbox,
        ) as mailbox:
            yield from mailbox.fetch(AND(date_gte=since_date))
