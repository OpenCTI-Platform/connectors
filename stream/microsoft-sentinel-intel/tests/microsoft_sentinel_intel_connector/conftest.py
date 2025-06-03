import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock

import pytest
from microsoft_sentinel_intel_connector.config import ConnectorSettings
from pytest_mock import MockerFixture


@pytest.fixture(name="mocked_api_client")
def fixture_mocked_helper(mocker: MockerFixture) -> MagicMock:
    return mocker.patch("pycti.connector.opencti_connector_helper.OpenCTIApiClient")


@pytest.fixture(name="microsoft_sentinel_intel_config_dict")
def fixture_microsoft_sentinel_intel_config_dict() -> dict[str, dict[str, str]]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "test-connector-id",
            "name": "External Import Connector Template",
            "type": "STREAM",
            "scope": "ChangeMe",
            "live_stream_id": "live-stream-id",
        },
        "microsoft_sentinel_intel": {
            "tenant_id": "ChangeMe",
            "client_id": "ChangeMe",
            "client_secret": "ChangeMe",
            "workspace_id": "ChangeMe",
            "workspace_name": "ChangeMe",
            "subscription_id": "ChangeMe",
            "resource_group": "default",
            "source_system": "Opencti Stream Connector",
            "delete_extensions": True,
            "extra_labels": "label",
            "workspace_api_version": "2024-02-01-preview",
            "management_api_version": "2025-03-01",
        },
    }


@pytest.fixture(name="mock_microsoft_sentinel_intel_config")
def fixture_mock_microsoft_sentinel_intel_config(
    mocker: MockerFixture,
    microsoft_sentinel_intel_config_dict: dict[str, dict[str, Any]],
) -> None:
    # Make sure the local config is not loaded in the tests
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in microsoft_sentinel_intel_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)
