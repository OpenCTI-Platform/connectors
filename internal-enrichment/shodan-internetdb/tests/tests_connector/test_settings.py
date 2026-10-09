from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from shodan_internetdb.settings import ConnectorSettings


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
                    "id": "00000000-0000-0000-0000-000000000000",
                    "name": "Shodan InternetDB",
                    "scope": "IPv4-Addr",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "TLP:WHITE",
                },
                "shodan": {
                    "ssl_verify": True,
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
                    "id": "00000000-0000-0000-0000-000000000000",
                },
                "shodan": {},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    accepts valid input.
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

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.shodan, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "00000000-0000-0000-0000-000000000000",
                },
                "shodan": {},
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
                "connector": {"id": 12345},
                "shodan": {},
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
                "connector": {
                    "id": "00000000-0000-0000-0000-000000000000",
                    "max_tlp": "INVALID_TLP_VALUE",
                },
                "shodan": {},
            },
            "connector.max_tlp",
            id="invalid_connector_max_tlp",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The field that is expected to cause the validation error
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake and invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


def test_settings_should_default_connector_max_tlp_to_tlp_white():
    """
    Test that `connector.max_tlp` (`CONNECTOR_MAX_TLP`) keeps the connector's historical default, `TLP:WHITE`.
    """

    # Given: A config dict that does not set max_tlp
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "00000000-0000-0000-0000-000000000000"},
                    "shodan": {},
                }
            )

    # When: The settings are loaded
    settings = FakeConnectorSettings()

    # Then: The default is TLP:WHITE
    assert settings.connector.max_tlp == "TLP:WHITE"


def test_settings_should_migrate_deprecated_shodan_max_tlp_to_connector_max_tlp():
    """
    Test that the deprecated `shodan.max_tlp` (`SHODAN_MAX_TLP`) is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """

    # Given: A config dict that still sets max_tlp in the shodan section
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "00000000-0000-0000-0000-000000000000"},
                    "shodan": {"max_tlp": "TLP:RED"},
                }
            )

    # When: The settings are loaded
    with pytest.warns(UserWarning, match="shodan.max_tlp"):
        settings = FakeConnectorSettings()

    # Then: The value is used as connector.max_tlp
    assert settings.connector.max_tlp == "TLP:RED"
