import warnings
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings


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
                    "name": "ZeroFox",
                    "scope": "zerofox",
                    "log_level": "error",
                    "duration_period": "PT5M",
                    "update_existing_data": False,
                },
                "zerofox": {
                    "username": "test-user",
                    "password": "test-password",
                    "collectors": "malware, ransomware",
                    "first_run": "P1D",
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
                },
                "zerofox": {
                    "username": "test-user",
                    "password": "test-password",
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
    assert isinstance(settings.zerofox, BaseConfigModel) is True


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
                "connector": {
                    "id": "connector-id",
                },
                "zerofox": {
                    "username": "test-user",
                    "password": "test-password",
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
                    "id": 12345,
                },
                "zerofox": {
                    "username": "test-user",
                    "password": "test-password",
                },
            },
            id="invalid_connector_id",
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
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


def test_settings_should_migrate_deprecated_run_every():
    """
    Test that the deprecated `CONNECTOR_RUN_EVERY` (e.g. '7d', '12h', '10m', '30s') is
    automatically migrated to `CONNECTOR_DURATION_PERIOD` via `DeprecatedField` metadata
    in `BaseConnectorSettings`.
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
                        "name": "ZeroFox",
                        "scope": "zerofox",
                        "run_every": "12h",
                    },
                    "zerofox": {
                        "username": "test-user",
                        "password": "test-password",
                    },
                }
            )

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(hours=12)
    warning_messages = [str(warning.message) for warning in w]
    assert any("run_every" in msg.lower() for msg in warning_messages)


def test_settings_should_migrate_deprecated_first_run():
    """
    Test that the deprecated `CONNECTOR_FIRST_RUN` (e.g. '7d', '12h', '10m', '30s') is
    automatically migrated to `ZEROFOX_FIRST_RUN` (a datetime relative to now) via
    `DeprecatedField` metadata in `BaseConnectorSettings`.
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
                        "name": "ZeroFox",
                        "scope": "zerofox",
                        "first_run": "2d",
                    },
                    "zerofox": {
                        "username": "test-user",
                        "password": "test-password",
                    },
                }
            )

    before_migration = datetime.now(timezone.utc) - timedelta(days=2)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()
    after_migration = datetime.now(timezone.utc) - timedelta(days=2)

    assert before_migration <= settings.zerofox.first_run <= after_migration
    warning_messages = [str(warning.message) for warning in w]
    assert any("first_run" in msg.lower() for msg in warning_messages)
