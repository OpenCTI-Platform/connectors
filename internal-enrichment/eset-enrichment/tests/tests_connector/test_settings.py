from copy import deepcopy
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
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
                    "max_tlp": "TLP:AMBER",
                },
                "eset": {
                    "api_key": "test-api-key",
                    "api_secret": "test-api-secret",
                    "api_host": "https://eti.eset.com/",
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
    assert settings.connector.max_tlp == TLPLevel.RED
    assert str(settings.eset.api_host) == "https://eti.eset.com/"
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
                "connector": {
                    "max_tlp": "bogus",
                },
                "eset": {
                    "api_key": "test-api-key",
                    "api_secret": "test-api-secret",
                },
            },
            id="invalid_connector_max_tlp",
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


def _settings_from(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            # The deprecation migration mutates the config dict in place
            return handler(deepcopy(settings_dict))

    return FakeConnectorSettings()


def test_settings_should_migrate_deprecated_connector_template_max_tlp():
    """`CONNECTOR_TEMPLATE_MAX_TLP` MUST be migrated to `CONNECTOR_MAX_TLP`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector_template": {"max_tlp": "TLP:GREEN"},
    }

    with pytest.warns(UserWarning, match="Migrating to 'connector.max_tlp'"):
        settings = _settings_from(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.GREEN


def test_settings_should_prefer_connector_max_tlp_over_deprecated_one():
    """`CONNECTOR_MAX_TLP` MUST win when both variables are set."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"max_tlp": "TLP:AMBER"},
        "connector_template": {"max_tlp": "TLP:GREEN"},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.max_tlp'"):
        settings = _settings_from(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.AMBER


def test_settings_should_reject_invalid_deprecated_connector_template_max_tlp():
    """A migrated value MUST be validated like `CONNECTOR_MAX_TLP`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector_template": {"max_tlp": "bogus"},
    }

    with pytest.warns(UserWarning), pytest.raises(ConfigValidationError):
        _settings_from(settings_dict)


def test_settings_should_not_migrate_other_connector_template_variables():
    """Only `CONNECTOR_TEMPLATE_MAX_TLP` MUST be migrated, other legacy variables are ignored."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector_template": {"api_key": "stale-api-key"},
    }

    settings = _settings_from(settings_dict)

    assert settings.eset.api_key.get_secret_value() == "test-api-key"
