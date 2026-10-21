import datetime
import os
from copy import deepcopy
from typing import Any

import pytest
from base_connector.errors import ConfigRetrievalError
from email_intel_microsoft.config import ConnectorSettings
from pydantic import HttpUrl, SecretStr
from pytest_mock import MockerFixture


@pytest.mark.usefixtures("mock_email_intel_microsoft_config")
def test_config() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    token = config["opencti"]["token"]
    if isinstance(token, SecretStr):
        assert token.get_secret_value() == "test-opencti-token"
    else:
        assert token == "test-opencti-token"

    assert config["connector"]["id"] == "test-connector-id"
    assert config["connector"]["name"] == "External Import Connector Template"
    assert config["connector"]["scope"] == ["ChangeMe"]
    assert config["connector"]["duration_period"] == datetime.timedelta(days=1)

    assert len(config["email_intel_microsoft"]) == 9
    assert config["email_intel_microsoft"]["tlp_level"] == "white"
    assert config["email_intel_microsoft"][
        "relative_import_start_date"
    ] == datetime.timedelta(days=30)
    assert config["email_intel_microsoft"]["tenant_id"] == "tenant-id"
    assert config["email_intel_microsoft"]["client_id"] == "client-id"
    assert (
        config["email_intel_microsoft"]["client_secret"].get_secret_value()
        == "client-secret"
    )
    assert config["email_intel_microsoft"]["email"] == "foo@bar.com"
    assert config["email_intel_microsoft"]["mailbox"] == "INBOX"
    assert config["email_intel_microsoft"]["attachments_mime_types"] == (
        ["application/pdf", "text/csv", "text/plain"]
    )
    assert config["email_intel_microsoft"]["report_type"] == "threat-report"


def test_config_invalid_report_type(
    mocker: MockerFixture, email_intel_config_dict: dict[str, dict[str, Any]]
) -> None:
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    email_intel_config_dict["email_intel_microsoft"]["report_type"] = "not-a-vocab"
    environ = deepcopy(os.environ)
    for key, value in email_intel_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)

    with pytest.raises(ConfigRetrievalError):
        ConnectorSettings()
