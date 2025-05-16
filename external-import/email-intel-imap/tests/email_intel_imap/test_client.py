import datetime
from unittest.mock import Mock

import pytest
from email_intel_imap.client import ConnectorClient


@pytest.fixture(name="client")
def fixture_client() -> ConnectorClient:
    return ConnectorClient(
        host="host",
        port=123,
        username="username",
        password="password",
        mailbox="mailbox",
    )


def test_client_fetch_from_relative_import_start_date(
    client: ConnectorClient, mocked_mail_box: Mock
) -> None:
    since_date = datetime.date(2023, 10, 1)

    result = client.fetch_from_relative_import_start_date(since_date=since_date)
    mocked_mail_box.fetch.assert_not_called()  # Make sure we have a Generator
    list(result)  # Consume the generator

    mocked_mail_box.fetch.assert_called_once_with(criteria="(SINCE 1-Oct-2023)")
