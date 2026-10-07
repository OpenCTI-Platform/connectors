from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from pure_signal_scout.settings import ConnectorSettings


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
                    "auto": True,
                    "max_tlp": "TLP:AMBER",
                },
                "pure_signal_scout": {
                    "api_url": "https://taxii.cymru.com/api/scout",
                    "api_token": "SecretStr",
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
                "pure_signal_scout": {"api_token": "SecretStr"},
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
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    # Given
    settings = FakeConnectorSettings()

    # When
    # Connector settings are loaded via FakeConnectorSettings initialization.

    # Then
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.pure_signal_scout, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "TLP:AMBER",
                },
                "pure_signal_scout": {
                    "api_url": "https://taxii.cymru.com/api/scout",
                    "api_token": "SecretStr",
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
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "TLP:AMBER",
                },
                "pure_signal_scout": {
                    "api_url": "https://taxii.cymru.com/api/scout",
                },
            },
            "pure_signal_scout.api_token",
            id="missing_api_token",
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

    # Given
    # Invalid settings dict provided via FakeConnectorSettings.

    # When
    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    # Then
    assert str("Error validating configuration") in str(err)


def test_settings_should_migrate_deprecated_pure_signal_scout_max_tlp_to_connector_max_tlp():
    """
    Test that the deprecated `pure_signal_scout.max_tlp` (`PURE_SIGNAL_SCOUT_MAX_TLP`)
    is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "pure_signal_scout": {
                        "api_token": "SecretStr",
                        "max_tlp": "TLP:RED",
                    },
                }
            )

    # Given
    # A config dict that still sets max_tlp in the pure_signal_scout section.

    # When
    with pytest.warns(UserWarning, match="pure_signal_scout.max_tlp"):
        settings = FakeConnectorSettings()

    # Then
    assert settings.connector.max_tlp == "TLP:RED"
