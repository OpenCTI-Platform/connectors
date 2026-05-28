import datetime
import json
from abc import ABC, abstractmethod
from typing import Generator

from base_connector import BaseClient
from google.auth.credentials import TokenState
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from imap_tools.mailbox import MailBox
from imap_tools.message import MailMessage
from imap_tools.query import AND
from pydantic import PrivateAttr


class BaseConnectorClient(BaseClient, ABC):
    """
    Base class for connector clients. This class defines the interface for fetching email messages.
    Subclasses should implement the `fetch_from_relative_import_start_date` method.
    """

    @abstractmethod
    def fetch_from_relative_import_start_date(
        self, since_date: datetime.date
    ) -> Generator[MailMessage, None, None]:
        """
        Abstract method to fetch email messages since a given date.

        Args:
            since_date (datetime.date): The date from which to begin retrieving emails.

        Yields:
            MailMessage: A parsed email message object representing one received email.
        """


class ConnectorClient(BaseConnectorClient):
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


class GoogleOAuthClient(BaseConnectorClient):
    host: str
    port: int
    username: str
    token_json: str
    mailbox: str

    _credentials: Credentials | None = PrivateAttr(default=None)

    def _refresh_credentials(self) -> None:
        # Note that the Google API library is not fully typed
        self._credentials: Credentials = Credentials.from_authorized_user_info(  # type: ignore[no-untyped-call]
            info=json.loads(self.token_json)
        )
        if not isinstance(self._credentials, Credentials):
            raise ValueError("Unable to retrieve credential.")
        if self._credentials.token_state != TokenState.FRESH:
            self._credentials.refresh(Request())  # type: ignore[no-untyped-call]

    def fetch_from_relative_import_start_date(
        self, since_date: datetime.date
    ) -> Generator[MailMessage, None, None]:
        """Implement fetch_from_relative_import_start_date method for Google OAuth2 authentication."""

        # always try to refresh the credentials before using them
        self._refresh_credentials()

        with MailBox(self.host, self.port).xoauth2(  # type: ignore[no-untyped-call]
            username=self.username,
            # self._credentials should exist as refresh_credentials is called before
            access_token=str(self._credentials.token),  # type: ignore[union-attr]
            initial_folder=self.mailbox,
        ) as mailbox:
            yield from mailbox.fetch(criteria=AND(date_gte=since_date))
