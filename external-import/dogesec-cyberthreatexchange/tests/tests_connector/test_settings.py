from copy import deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "cyberthreatexchange": {
        "api_key": "test-api-key",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or `config.yml`."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return the given config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(deepcopy(settings_dict))

    return FakeConnectorSettings()


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
                    "name": "CyberThreatExchange",
                    "scope": "cyberthreatexchange",
                    "log_level": "info",
                    "duration_period": "PT12H",
                },
                "cyberthreatexchange": {
                    "base_url": "https://api.cyberthreatexchange.com/",
                    "api_key": "test-api-key",
                    "feed_ids": "feed-1,feed-2",
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
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.cyberthreatexchange, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """Test that optional fields fall back on their documented defaults."""
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "CyberThreatExchange"
    assert settings.connector.scope == ["cyberthreatexchange"]
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert (
        str(settings.cyberthreatexchange.base_url)
        == "https://api.cyberthreatexchange.com/"
    )
    assert settings.cyberthreatexchange.feed_ids == []


def test_settings_should_parse_feed_ids():
    """Test that the comma-separated feed IDs are parsed into a list."""
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "cyberthreatexchange": {
                "api_key": "test-api-key",
                "feed_ids": "feed-1, feed-2",
            },
        }
    )

    assert settings.cyberthreatexchange.feed_ids == ["feed-1", "feed-2"]
    assert settings.cyberthreatexchange.api_key.get_secret_value() == "test-api-key"


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = build_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    assert settings.connector.id == "b51736f7-7ed8-4c41-b247-eadd836f4f6c"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "cyberthreatexchange": {
                    "api_key": "test-api-key",
                    "feed_ids": "feed-1",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123456},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "cyberthreatexchange": {"feed_ids": "feed-1"},
            },
            id="missing_cyberthreatexchange_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)
    assert "Error validating configuration" in str(err.value)


def test_settings_should_migrate_deprecated_interval_hours():
    """The legacy `CYBERTHREATEXCHANGE_INTERVAL_HOURS` MUST migrate to `CONNECTOR_DURATION_PERIOD`."""
    with pytest.warns(UserWarning, match="cyberthreatexchange.interval_hours"):
        settings = build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "cyberthreatexchange": {
                    **MINIMAL_VALID_SETTINGS_DICT["cyberthreatexchange"],
                    "interval_hours": 12,
                },
            }
        )

    assert settings.connector.duration_period == timedelta(hours=12)


def test_settings_should_prefer_duration_period_over_interval_hours():
    """When both are set, `CONNECTOR_DURATION_PERIOD` MUST win over the legacy interval."""
    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "PT6H"},
                "cyberthreatexchange": {
                    **MINIMAL_VALID_SETTINGS_DICT["cyberthreatexchange"],
                    "interval_hours": 12,
                },
            }
        )

    assert settings.connector.duration_period == timedelta(hours=6)


@pytest.mark.parametrize(
    "base_url",
    ["api.example.com", "ftp://api.example.com", "not a url"],
)
def test_settings_should_reject_invalid_base_url(base_url):
    """`cyberthreatexchange.base_url` must be an absolute HTTP(S) URL."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "cyberthreatexchange": {
            **MINIMAL_VALID_SETTINGS_DICT["cyberthreatexchange"],
            "base_url": base_url,
        },
    }

    with pytest.raises(ConfigValidationError):
        build_settings(settings_dict)
