import os
from copy import deepcopy
from typing import Any

import pytest
from email_intel_microsoft.config import ConnectorSettings
from pytest_mock import MockerFixture


@pytest.fixture(name="email_intel_config_dict")
def fixture_email_intel_config_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "test-connector-id",
            "name": "External Import Connector Template",
            "type": "EXTERNAL_IMPORT",
            "scope": "ChangeMe",
            "duration_period": "P1D",
        },
        "email_intel_microsoft": {
            "tlp_level": "white",
            "relative_import_start_date": "P30D",
            "tenant_id": "tenant-id",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "email": "foo@bar.com",
            "mailbox": "INBOX",
            "attachments_mime_types": "application/pdf,text/csv,text/plain",
        },
    }


@pytest.fixture(name="mock_email_intel_microsoft_config")
def fixture_mock_email_intel_microsoft_config(
    mocker: MockerFixture, email_intel_config_dict: dict[str, dict[str, Any]]
) -> None:
    # Make sure the local config is not loaded in the tests
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in email_intel_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)
