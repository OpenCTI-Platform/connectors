import datetime

import pytest
from email_intel_imap.config import ConnectorConfig
from pycti import ConnectorType
from pydantic import HttpUrl


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_config() -> None:
    config = ConnectorConfig().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "test-opencti-token"

    assert config["connector"]["id"] == "test-connector-id"
    assert config["connector"]["name"] == "External Import Connector Template"
    assert config["connector"]["type"] == ConnectorType.EXTERNAL_IMPORT
    assert config["connector"]["scope"] == ["ChangeMe"]
    assert config["connector"]["duration_period"] == datetime.timedelta(days=1)

    assert config["email_intel_imap"]["tlp_level"] == "white"
