from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from cybersixgill.settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "cybersixgill": {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "update_existing_data": True,
                    "duration_period": "PT10M",
                },
                "cybersixgill": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "create_observables": True,
                    "create_indicators": True,
                    "enable_relationships": True,
                    "fetch_size": 2000,
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
    assert isinstance(settings.cybersixgill, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """
    Test that `ConnectorSettings` applies the documented defaults for optional Cybersixgill fields.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.name == "Cybersixgill Darkfeed"
    assert settings.connector.scope == ["cybersixgill"]
    assert settings.connector.update_existing_data is False
    assert settings.connector.duration_period == timedelta(minutes=5)
    assert settings.cybersixgill.client_secret.get_secret_value() == (
        "test-client-secret"
    )
    assert settings.cybersixgill.create_observables is True
    assert settings.cybersixgill.create_indicators is True
    assert settings.cybersixgill.enable_relationships is True
    assert settings.cybersixgill.fetch_size == 2000


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "4a843046-945d-4855-94ce-ead2bf5c8710"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_migrate_deprecated_interval_sec():
    """`CYBERSIXGILL_INTERVAL_SEC` MUST be migrated to `CONNECTOR_DURATION_PERIOD`."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "cybersixgill": {
                        **MINIMAL_VALID_SETTINGS_DICT["cybersixgill"],
                        "interval_sec": "600",
                    },
                }
            )

    with pytest.warns(UserWarning, match="cybersixgill.interval_sec"):
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(seconds=600)


def test_settings_should_prefer_duration_period_over_deprecated_interval_sec():
    """`CONNECTOR_DURATION_PERIOD` MUST win when both variables are set."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "connector": {"duration_period": "PT1H"},
                    "cybersixgill": {
                        **MINIMAL_VALID_SETTINGS_DICT["cybersixgill"],
                        "interval_sec": 600,
                    },
                }
            )

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(hours=1)


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                },
                "cybersixgill": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                },
                "cybersixgill": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "cybersixgill": {"client_id": "test-client-id"},
            },
            "cybersixgill.client_secret",
            id="missing_cybersixgill_client_secret",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The name of the field that should raise the error
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
