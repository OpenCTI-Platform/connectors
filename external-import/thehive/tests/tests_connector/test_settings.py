from datetime import timedelta
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "thehive",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "thehive": {
                    "url": "https://thehive.example.com",
                    "api_key": "test-api-key",
                    "organization_name": "TestOrg",
                    "check_ssl": True,
                    "import_only_tlp": "0,1,2,3,4",
                    "import_alerts": True,
                    "import_attachments": False,
                    "severity_mapping": "1:01 - low,2:02 - medium,3:03 - high,4:04 - critical",
                    "case_status_mapping": "",
                    "case_tag_whitelist": "",
                    "task_status_mapping": "",
                    "alert_status_mapping": "",
                    "user_mapping": "",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "thehive": {
                    "url": "https://thehive.example.com",
                    "api_key": "test-api-key",
                    "organization_name": "TestOrg",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.thehive, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "thehive",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "thehive": {
                    "url": "https://thehive.example.com",
                    "api_key": "test-api-key",
                    "organization_name": "TestOrg",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "thehive",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "thehive": {
                    "url": "https://thehive.example.com",
                    "api_key": "test-api-key",
                    "organization_name": "TestOrg",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "thehive": {
                    "api_key": "test-api-key",
                    "organization_name": "TestOrg",
                },
            },
            "thehive.url",
            id="missing_thehive_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "thehive": {
                    "url": "https://thehive.example.com",
                    "organization_name": "TestOrg",
                },
            },
            "thehive.api_key",
            id="missing_thehive_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "thehive": {
                    "url": "https://thehive.example.com",
                    "api_key": "test-api-key",
                },
            },
            "thehive.organization_name",
            id="missing_thehive_organization_name",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


def test_settings_should_migrate_deprecated_interval():
    """
    Test that the deprecated `THEHIVE_INTERVAL` (minutes) is automatically migrated
    to `CONNECTOR_DURATION_PERIOD` via `DeprecatedField` metadata in `BaseConnectorSettings`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {
                        "id": "connector-id",
                        "name": "Test Connector",
                        "scope": "thehive",
                    },
                    "thehive": {
                        "url": "https://thehive.example.com",
                        "api_key": "test-api-key",
                        "organization_name": "TestOrg",
                        "interval": 10,
                    },
                }
            )

    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(minutes=10)
    warning_messages = [str(warning.message) for warning in w]
    assert any("interval" in msg.lower() for msg in warning_messages)
