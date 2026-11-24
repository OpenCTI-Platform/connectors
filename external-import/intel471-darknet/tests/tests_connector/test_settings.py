from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings, run_every_to_timedelta

CONNECTOR_ID_DEFAULT = "5dbd8814-52af-46ee-a319-e2b98ceccef0"

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "intel471": {
        "api_username": "test-username",
        "api_key": "test-api-key",
    },
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "test, connector",
        "log_level": "error",
        "duration_period": "PT5M",
    },
    "intel471": {
        "api_url": "https://intel471.test/v1",
        "api_username": "test-username",
        "api_key": "test-api-key",
    },
    "intel471_darknet": {
        "initial_history_alerts": 1700000000,
        "tlp": "RED",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or config files."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.intel471, BaseConfigModel) is True
    assert isinstance(settings.intel471_darknet, BaseConfigModel) is True


def test_settings_should_read_every_field():
    settings = build_settings(FULL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "connector-id"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test", "connector"]
    assert settings.connector.duration_period == timedelta(minutes=5)
    assert settings.intel471.api_url == "https://intel471.test/v1"
    assert settings.intel471.api_username == "test-username"
    assert settings.intel471.api_key.get_secret_value() == "test-api-key"
    assert settings.intel471_darknet.initial_history_alerts == 1700000000
    assert settings.intel471_darknet.tlp == "RED"


def test_settings_should_apply_defaults():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Intel 471 Darknet"
    assert settings.connector.scope == ["intel471-darknet"]
    assert settings.connector.log_level == "error"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(minutes=10)
    assert settings.intel471.api_url == "https://api.intel471.com/v1"
    assert settings.intel471_darknet.initial_history_alerts == 0
    assert settings.intel471_darknet.tlp == "AMBER"


def test_settings_should_default_connector_id():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == CONNECTOR_ID_DEFAULT
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"id": 123456}},
            id="connector_id_as_int",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "intel471": {"api_key": "test-api-key"}},
            id="missing_intel471_api_username",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "intel471": {"api_username": "test-username"},
            },
            id="missing_intel471_api_key",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "intel471_darknet": {"initial_history_alerts": "yesterday"},
            },
            id="initial_history_alerts_not_an_int",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err.value)


def test_settings_should_migrate_deprecated_run_every():
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"run_every": "2h"},
    }

    with pytest.warns(UserWarning, match="connector.run_every"):
        settings = build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(hours=2)


def test_settings_should_prefer_duration_period_over_run_every():
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"run_every": "2h", "duration_period": "PT15M"},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(minutes=15)


@pytest.mark.parametrize(
    "run_every, expected",
    [
        pytest.param("30s", timedelta(seconds=30), id="seconds"),
        pytest.param("10m", timedelta(minutes=10), id="minutes"),
        pytest.param("12h", timedelta(hours=12), id="hours"),
        pytest.param("7d", timedelta(days=7), id="days"),
        pytest.param(" 5M ", timedelta(minutes=5), id="case_and_spaces"),
    ],
)
def test_run_every_to_timedelta_should_convert_legacy_values(run_every, expected):
    assert run_every_to_timedelta(run_every) == expected


@pytest.mark.parametrize("run_every", ["", "10", "m", "10w", "1.5h"])
def test_run_every_to_timedelta_should_raise_on_invalid_values(run_every):
    with pytest.raises(ValueError, match="Invalid CONNECTOR_RUN_EVERY value"):
        run_every_to_timedelta(run_every)


def test_settings_should_map_overlapping_section_env_vars(monkeypatch):
    """`INTEL471_DARKNET_*` variables MUST reach the `intel471_darknet` section,
    even though the `intel471` section name is a prefix of it."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("INTEL471_API_URL", "http://fake-api:8000/v1")
    monkeypatch.setenv("INTEL471_API_USERNAME", "env-username")
    monkeypatch.setenv("INTEL471_API_KEY", "env-api-key")
    monkeypatch.setenv("INTEL471_DARKNET_INITIAL_HISTORY_ALERTS", "1700000000")
    monkeypatch.setenv("INTEL471_DARKNET_TLP", "GREEN")

    settings = ConnectorSettings()

    assert settings.intel471.api_url == "http://fake-api:8000/v1"
    assert settings.intel471.api_username == "env-username"
    assert settings.intel471.api_key.get_secret_value() == "env-api-key"
    assert settings.intel471_darknet.initial_history_alerts == 1700000000
    assert settings.intel471_darknet.tlp == "GREEN"
