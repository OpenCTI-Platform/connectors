from typing import Any
from uuid import UUID

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
                    "auto": True,
                },
                "visionheight": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "max_tlp_level": "clear",
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
                "visionheight": {
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
    assert isinstance(settings.visionheight, BaseConfigModel) is True


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
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "visionheight": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "max_tlp_level": "clear",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {},
                "visionheight": {
                    "api_key": "test-api-key",
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
                    "id": 1234,  # must be a string, not an int
                },
                "visionheight": {
                    "api_key": "test-api-key",
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
                "visionheight": {},  # api_key is required and has no default
            },
            "visionheight.api_key",
            id="missing_visionheight_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "visionheight": {
                    "api_key": "test-api-key",
                    "max_tlp_level": "purple",  # not a valid TLP level
                },
            },
            "visionheight.max_tlp_level",
            id="invalid_visionheight_max_tlp_level",
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


def test_settings_should_default_connector_id():
    """
    Test that `connector.id` falls back on the connector's own unique default UUID v4.

    `_BaseConnectorConfig.id` is declared required with no default in `connectors-sdk`.
    `InternalEnrichmentConnectorConfig` overrides it so the connector can be deployed
    from the catalog without the user having to provide a CONNECTOR_ID.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict
        whose `connector` section is empty, so every connector field falls back on its default.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {},
                    "visionheight": {
                        "api_key": "test-api-key",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.connector.id == "72de5a27-4619-4189-a66b-ad89819b200a"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_default_connector_name_and_scope():
    """
    Test that `connector.name` and `connector.scope` fall back on the connector's own defaults,
    and that `scope` is parsed from a comma-separated string into a list of strings.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {},
                    "visionheight": {
                        "api_key": "test-api-key",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.connector.name == "VisionHeight"
    assert settings.connector.scope == ["IPv4-Addr", "Domain-Name"]
    # `pycti` expects a comma-separated string, not a list
    assert settings.to_helper_config()["connector"]["scope"] == "IPv4-Addr,Domain-Name"


def test_settings_should_keep_api_key_secret():
    """
    Test that `visionheight.api_key` is a `SecretStr`: it must not leak in the string
    representation of the settings, and must be readable via `get_secret_value()`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {},
                    "visionheight": {
                        "api_key": "super-secret-api-key",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.visionheight.api_key.get_secret_value() == "super-secret-api-key"
    assert "super-secret-api-key" not in str(settings.visionheight)
