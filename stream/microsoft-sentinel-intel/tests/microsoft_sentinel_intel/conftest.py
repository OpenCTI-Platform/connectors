import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock

import pytest
from microsoft_sentinel_intel.settings import ConnectorSettings
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
            "batch_mode": False,
            "batch_size": 100,
            "batch_timeout": 30,
            "event_types": "create,update,delete",
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


@pytest.fixture(name="microsoft_sentinel_intel_batch_config_dict")
def fixture_microsoft_sentinel_intel_batch_config_dict(
    microsoft_sentinel_intel_config_dict: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    config = deepcopy(microsoft_sentinel_intel_config_dict)
    config["microsoft_sentinel_intel"]["batch_mode"] = True
    config["microsoft_sentinel_intel"]["batch_size"] = 3
    config["microsoft_sentinel_intel"]["batch_timeout"] = 2
    return config


@pytest.fixture(name="mock_microsoft_sentinel_intel_batch_config")
def fixture_mock_microsoft_sentinel_intel_batch_config(
    mocker: MockerFixture,
    microsoft_sentinel_intel_batch_config_dict: dict[str, dict[str, Any]],
) -> None:
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in microsoft_sentinel_intel_batch_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


def _make_config_with_event_types(
    base_config: dict[str, dict[str, Any]],
    event_types: str,
) -> dict[str, dict[str, Any]]:
    config = deepcopy(base_config)
    config["microsoft_sentinel_intel"]["event_types"] = event_types
    return config


def _mock_config_environ(
    mocker: MockerFixture,
    config_dict: dict[str, dict[str, Any]],
) -> None:
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="microsoft_sentinel_intel_create_update_only_config_dict")
def fixture_microsoft_sentinel_intel_create_update_only_config_dict(
    microsoft_sentinel_intel_config_dict: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return _make_config_with_event_types(microsoft_sentinel_intel_config_dict, "create,update")


@pytest.fixture(name="mock_microsoft_sentinel_intel_create_update_only_config")
def fixture_mock_microsoft_sentinel_intel_create_update_only_config(
    mocker: MockerFixture,
    microsoft_sentinel_intel_create_update_only_config_dict: dict[str, dict[str, Any]],
) -> None:
    _mock_config_environ(mocker, microsoft_sentinel_intel_create_update_only_config_dict)


@pytest.fixture(name="microsoft_sentinel_intel_delete_only_config_dict")
def fixture_microsoft_sentinel_intel_delete_only_config_dict(
    microsoft_sentinel_intel_config_dict: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return _make_config_with_event_types(microsoft_sentinel_intel_config_dict, "delete")


@pytest.fixture(name="mock_microsoft_sentinel_intel_delete_only_config")
def fixture_mock_microsoft_sentinel_intel_delete_only_config(
    mocker: MockerFixture,
    microsoft_sentinel_intel_delete_only_config_dict: dict[str, dict[str, Any]],
) -> None:
    _mock_config_environ(mocker, microsoft_sentinel_intel_delete_only_config_dict)


@pytest.fixture(name="microsoft_sentinel_intel_batch_create_only_config_dict")
def fixture_microsoft_sentinel_intel_batch_create_only_config_dict(
    microsoft_sentinel_intel_batch_config_dict: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return _make_config_with_event_types(microsoft_sentinel_intel_batch_config_dict, "create")


@pytest.fixture(name="mock_microsoft_sentinel_intel_batch_create_only_config")
def fixture_mock_microsoft_sentinel_intel_batch_create_only_config(
    mocker: MockerFixture,
    microsoft_sentinel_intel_batch_create_only_config_dict: dict[str, dict[str, Any]],
) -> None:
    _mock_config_environ(mocker, microsoft_sentinel_intel_batch_create_only_config_dict)
