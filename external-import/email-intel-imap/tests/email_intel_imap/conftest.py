import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from email_intel_imap.config import ConnectorConfig
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
        "email_intel_imap": {
            "tlp_level": "white",
            "relative_import_start_date": "P30D",
            "host": "imap.test.com",
            "port": 993,
            "username": "foo",
            "password": "bar",
            "mailbox": "INBOX",
            "attachments_mime_types": "application/pdf,text/csv,text/plain",
        },
    }


@pytest.fixture(name="mock_email_intel_imap_config")
def fixture_mock_email_intel_imap_config(
    mocker: MockerFixture, email_intel_config_dict: dict[str, dict[str, Any]]
) -> None:
    # Make sure the local config is not loaded in the tests
    ConnectorConfig.model_config["yaml_file"] = ""
    ConnectorConfig.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in email_intel_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    return mocker.patch("pycti.OpenCTIConnectorHelper", Mock())


@pytest.fixture(name="mocked_mail_box")
def fixture_mocked_mail_box(mocker: MockerFixture) -> MagicMock:
    mocked_mail_box = mocker.patch("email_intel_imap.client.MailBox")
    mocked_mail_box_instance = MagicMock()
    mocked_mail_box.return_value.login.return_value.__enter__.return_value = (
        mocked_mail_box_instance
    )
    return mocked_mail_box_instance


@pytest.fixture(name="test_config")
def fixture_test_config(
    mock_email_intel_imap_config: None,
) -> ConnectorConfig:
    return ConnectorConfig()
