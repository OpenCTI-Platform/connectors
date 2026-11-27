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
    "obstracts": {
        "api_key": "test-api-key",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or config files."""

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
                    "name": "Obstracts",
                    "scope": "obstracts",
                    "log_level": "error",
                    "duration_period": "PT12H",
                },
                "obstracts": {
                    "base_url": "https://api.obstracts.com/",
                    "api_key": "test-api-key",
                    "feed_ids": "feed-1,feed-2",
                    "days_to_backfill": 90,
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
    assert isinstance(settings.obstracts, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """Optional fields MUST fall back on their documented defaults."""
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Obstracts"
    assert settings.connector.scope == ["obstracts"]
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert str(settings.obstracts.base_url) == "https://api.obstracts.com/"
    assert settings.obstracts.api_key.get_secret_value() == "test-api-key"
    assert settings.obstracts.feed_ids == []
    assert settings.obstracts.days_to_backfill == 7


def test_settings_should_parse_feed_ids():
    """`OBSTRACTS_FEED_IDS` MUST be split on commas, as the legacy code did."""
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "obstracts": {"api_key": "test-api-key", "feed_ids": "feed-1, feed-2"},
        }
    )

    assert settings.obstracts.feed_ids == ["feed-1", "feed-2"]


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = build_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    assert settings.connector.id == "cdef318a-d5cf-4363-8ea3-b96aa360ab78"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "obstracts": {"api_key": "test-api-key"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "obstracts": {"api_key": "test-api-key"},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "obstracts": {},
            },
            id="missing_obstracts_api_key",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "obstracts": {"api_key": "test-api-key", "days_to_backfill": "ten"},
            },
            id="invalid_obstracts_days_to_backfill",
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
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err.value)


def test_settings_should_migrate_deprecated_interval_hours():
    """`OBSTRACTS_INTERVAL_HOURS` MUST be migrated to `CONNECTOR_DURATION_PERIOD`."""
    with pytest.warns(UserWarning, match="obstracts.interval_hours"):
        settings = build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "obstracts": {"api_key": "test-api-key", "interval_hours": "12"},
            }
        )

    assert settings.connector.duration_period == timedelta(hours=12)


def test_settings_should_prefer_duration_period_over_deprecated_interval_hours():
    """`CONNECTOR_DURATION_PERIOD` MUST win when both variables are set."""
    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "PT2H"},
                "obstracts": {"api_key": "test-api-key", "interval_hours": "12"},
            }
        )

    assert settings.connector.duration_period == timedelta(hours=2)


@pytest.mark.parametrize(
    "base_url",
    ["api.example.com", "ftp://api.example.com", "not a url"],
)
def test_settings_should_reject_invalid_base_url(base_url):
    """`obstracts.base_url` must be an absolute HTTP(S) URL."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "obstracts": {**MINIMAL_VALID_SETTINGS_DICT["obstracts"], "base_url": base_url},
    }

    with pytest.raises(ConfigValidationError):
        build_settings(settings_dict)
