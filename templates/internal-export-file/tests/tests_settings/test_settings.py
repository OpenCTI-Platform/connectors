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
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "template": {
                    "api_key": "test-api-key",
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
                "connector": {
                    "id": "connector-id",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "template": {
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    # Given: Valid input
    class FakeConnectorSettings(ConnectorSettings):
        def _load_config_dict(self, _) -> dict[str, Any]:
            return settings_dict

    # When: We create an ConnectorSettings instance with valid input data
    settings = FakeConnectorSettings()

    # Then: The ConnectorSettings instance should be created successfully
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.template, BaseConfigModel) is True


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
                    "url": "http://localhost:PORT",  # invalid URL
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "template": {
                    "api_key": "test-api-key",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "template": {
                    "api_key": "test-api-key",
                },
            },
            "connector.id",
            id="missing_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    # Given: Empty input
    class FakeConnectorSettings(ConnectorSettings):
        def _load_settings_dict(self, _) -> dict[str, Any]:
            return settings_dict

    # When: We try to create an ConnectorSettings instance with invalid data
    # Then: A ConfigValidationError should be raised, and the error field should be in the error message
    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
