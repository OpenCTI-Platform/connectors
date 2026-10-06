from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from eset.settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "eset": {
        "api_key": "test-api-key",
        "api_secret": "test-api-secret",
    },
}


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
                    "name": "ESET ETI Report Enrichment Connector",
                    "scope": "report",
                    "log_level": "error",
                    "auto": True,
                },
                "eset": {
                    "api_key": "test-api-key",
                    "api_secret": "test-api-secret",
                    "api_host": "https://eti.eset.com/",
                    "max_tlp": "TLP:AMBER",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            MINIMAL_VALID_SETTINGS_DICT,
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
    assert isinstance(settings.eset, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """
    Test that `ConnectorSettings` applies the defaults of the optional fields.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.name == "ESET ETI Report Enrichment Connector"
    assert settings.connector.scope == ["report"]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.auto is False
    assert str(settings.eset.api_host) == "https://eti.eset.com/"
    assert settings.eset.max_tlp is None
    assert settings.eset.api_key.get_secret_value() == "test-api-key"
    assert settings.eset.api_secret.get_secret_value() == "test-api-secret"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {},
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {},
                "eset": {
                    "api_key": "test-api-key",
                    "api_secret": "test-api-secret",
                },
            },
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
                },
                "eset": {
                    "api_key": "test-api-key",
                    "api_secret": "test-api-secret",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "eset": {
                    "api_key": "test-api-key",
                },
            },
            id="missing_eset_api_secret",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "eset": {
                    "api_key": "test-api-key",
                    "api_secret": "test-api-secret",
                    "max_tlp": "amber",
                },
            },
            id="invalid_eset_max_tlp",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
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
    assert "Error validating configuration" in str(err)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "a4df8389-6ba4-4e2c-b09e-f8014f0d0af1"
    assert UUID(settings.connector.id).version == 4
