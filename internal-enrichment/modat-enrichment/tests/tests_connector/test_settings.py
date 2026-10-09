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
                    "scope": "ipv4-addr",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "TLP:CLEAR",
                },
                "modat": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "include_cves": True,
                    "max_services_in_summary": 10,
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
                    "scope": "ipv4-addr",
                },
                "modat": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
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

    # Given: Valid input
    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    # When: We create an ConnectorSettings instance with valid input data
    settings = FakeConnectorSettings()

    # Then: The ConnectorSettings instance should be created successfully
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.modat, BaseConfigModel) is True


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
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "ipv4-addr",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "TLP:CLEAR",
                },
                "modat": {
                    "api_base_url": "http://test.com",
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
                    "scope": "ipv4-addr",
                    "log_level": "error",
                    "auto": True,
                },
                "modat": {
                    "api_base_url": "http://test.com",
                },
            },
            "modat.api_key",
            id="missing_modat_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


def test_settings_should_migrate_deprecated_modat_max_tlp_to_connector_max_tlp():
    """
    Test that the deprecated `modat.max_tlp` (`MODAT_MAX_TLP`) is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """

    # Given: A config dict that still sets max_tlp in the modat section
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "modat": {"api_key": "test-api-key", "max_tlp": "TLP:RED"},
                }
            )

    # When: The settings are loaded
    with pytest.warns(UserWarning, match="modat.max_tlp"):
        settings = FakeConnectorSettings()

    # Then: The value is used as connector.max_tlp
    assert settings.connector.max_tlp == "TLP:RED"
