import datetime

import pytest
from email_intel_microsoft.config import ConnectorSettings
from pydantic import HttpUrl


@pytest.mark.usefixtures("mock_email_intel_microsoft_config")
def test_config() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "test-opencti-token"

    assert config["connector"]["id"] == "test-connector-id"
    assert config["connector"]["name"] == "External Import Connector Template"
    assert config["connector"]["scope"] == ["ChangeMe"]
    assert config["connector"]["duration_period"] == datetime.timedelta(days=1)

    assert len(config["email_intel_microsoft"]) == 8
    assert config["email_intel_microsoft"]["tlp_level"] == "white"
    assert config["email_intel_microsoft"][
        "relative_import_start_date"
    ] == datetime.timedelta(days=30)
    assert config["email_intel_microsoft"]["tenant_id"] == "tenant-id"
    assert config["email_intel_microsoft"]["client_id"] == "client-id"
    assert config["email_intel_microsoft"]["client_secret"] == "client-secret"
    assert config["email_intel_microsoft"]["email"] == "foo@bar.com"
    assert config["email_intel_microsoft"]["mailbox"] == "INBOX"
    assert config["email_intel_microsoft"]["attachments_mime_types"] == (
        ["application/pdf", "text/csv", "text/plain"]
    )
