import datetime
from unittest.mock import Mock

import pytest
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_client(mocked_helper: Mock):
    client = ConnectorClient(config=ConnectorConfig(), helper=mocked_helper)
    assert client


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_client_fetch_from_relative_import_start_date(
    mocked_helper: Mock, mocked_mail_box: Mock
) -> None:
    client = ConnectorClient(config=ConnectorConfig(), helper=mocked_helper)

    result = client.fetch_from_relative_import_start_date()
    mocked_mail_box.fetch.assert_not_called()  # Make sure we have a Generator
    list(result)  # Consume the generator

    today = datetime.date.today()
    delta = client.config.email_intel_imap.relative_import_start_date
    delta_date = today - delta

    mocked_mail_box.fetch.assert_called_once_with(
        f"(SINCE {delta_date.strftime('%d-%b-%Y')})"
    )
