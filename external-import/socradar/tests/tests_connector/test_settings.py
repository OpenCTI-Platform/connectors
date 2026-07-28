import warnings
from datetime import timedelta
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

FULL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "SOCRadar",
        "scope": "socradar",
        "log_level": "error",
        "duration_period": "PT10M",
    },
    "radar": {
        "base_feed_url": "https://platform.socradar.com/api/threat/intelligence/feed_list/",
        "socradar_key": "test-api-key",
        "feed_lists": {"feed_list_1": "ID_1", "feed_list_2": "ID_2"},
    },
}

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id"},
    "radar": {
        "base_feed_url": "https://platform.socradar.com/api/threat/intelligence/feed_list/",
        "socradar_key": "test-api-key",
        "feed_lists": {"feed_list_1": "ID_1"},
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts
    valid input.
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
    assert isinstance(settings.radar, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "SOCRadar",
                    "scope": "socradar",
                    "log_level": "error",
                    "duration_period": "PT10M",
                },
                "radar": {
                    "base_feed_url": "https://x/",
                    "socradar_key": "test-api-key",
                    "feed_lists": {"feed_list_1": "ID_1"},
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
                    "name": "SOCRadar",
                    "scope": "socradar",
                    "log_level": "error",
                    "duration_period": "PT10M",
                },
                "radar": {
                    "base_feed_url": "https://x/",
                    "socradar_key": "test-api-key",
                    "feed_lists": {"feed_list_1": "ID_1"},
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises
    on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The field name that is invalid (unused at runtime, serves as test documentation)
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


def test_settings_should_migrate_deprecated_interval():
    """
    Test that the deprecated `RADAR_RUN_INTERVAL` field is migrated to
    `CONNECTOR_DURATION_PERIOD` automatically via the SDK's deprecation mechanism.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "name": "SOCRadar",
                        "scope": "socradar",
                    },
                    "radar": {
                        "base_feed_url": "https://x/",
                        "socradar_key": "test-api-key",
                        "feed_lists": {"feed_list_1": "ID_1"},
                        "run_interval": 7200,
                    },
                }
            )

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(seconds=7200)
    warning_messages = [str(warning.message) for warning in w]
    assert any("interval" in msg.lower() for msg in warning_messages)
