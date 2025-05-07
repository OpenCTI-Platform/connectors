import datetime

import pytest
from email_intel_imap.config import ConnectorSettings
from pydantic import HttpUrl


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_config() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "test-opencti-token"

    assert config["connector"]["id"] == "test-connector-id"
    assert config["connector"]["name"] == "External Import Connector Template"
    assert config["connector"]["type"] == "EXTERNAL_IMPORT"
    assert config["connector"]["scope"] == ["ChangeMe"]
    assert config["connector"]["duration_period"] == datetime.timedelta(days=1)

    assert config["email_intel_imap"]["tlp_level"] == "white"
    assert config["email_intel_imap"][
        "relative_import_start_date"
    ] == datetime.timedelta(days=30)
    assert config["email_intel_imap"]["host"] == "imap.test.com"
    assert config["email_intel_imap"]["port"] == 993
    assert config["email_intel_imap"]["username"] == "foo"
    assert config["email_intel_imap"]["password"] == "bar"
    assert config["email_intel_imap"]["mailbox"] == "INBOX"
    assert config["email_intel_imap"]["attachments_mime_types"] == (
        ["application/pdf", "text/csv", "text/plain"]
    )
