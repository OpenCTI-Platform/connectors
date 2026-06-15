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
                    "scope": "StixFile,Artifact",
                    "log_level": "error",
                    "auto": True,
                },
                "fortisandbox": {
                    "api_base_url": "https://fsa.example.com",
                    "username": "api-user",
                    "password": "api-pass",
                    "max_tlp": "TLP:CLEAR",
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
                    "scope": "StixFile,Artifact",
                },
                "fortisandbox": {
                    "api_base_url": "https://fsa.example.com",
                    "username": "api-user",
                    "password": "api-pass",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.fortisandbox, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, expected_loc",
    [
        # No specific field: the whole config is empty, so just assert it is rejected.
        pytest.param({}, None, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "StixFile,Artifact",
                },
                "fortisandbox": {
                    "username": "api-user",
                    "password": "api-pass",
                },
            },
            "api_base_url",
            id="missing_api_base_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "name": "Test Connector",
                    "scope": "StixFile,Artifact",
                },
                "fortisandbox": {
                    "api_base_url": "https://fsa.example.com",
                    "username": "api-user",
                    "password": "api-pass",
                },
            },
            "id",
            id="missing_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, expected_loc):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    # match= asserts on the real exception message (not the pytest ExceptionInfo repr).
    with pytest.raises(
        ConfigValidationError, match="Error validating configuration"
    ) as err:
        FakeConnectorSettings()
    # For field-specific cases, assert the offending field is named in the wrapped
    # pydantic validation error so the test verifies the *right* field is rejected.
    if expected_loc is not None:
        assert expected_loc in str(err.value.__cause__)
