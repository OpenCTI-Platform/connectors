from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "ClickHouse",
            "scope": "clickhouse",
            "log_level": "error",
            "live_stream_id": "live",
        },
        "clickhouse": {
            "base_url": "http://clickhouse:8123",
            "password": "test-password",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.clickhouse, BaseConfigModel) is True


def test_settings_should_apply_clickhouse_defaults():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert settings.clickhouse.username == "default"
    assert settings.clickhouse.database == "default"
    assert settings.clickhouse.table == "opencti_stream"
    assert settings.clickhouse.create_table is True
    assert settings.clickhouse.ssl_verify is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "clickhouse",
                    "live_stream_id": "live",
                },
                "clickhouse": {"password": "test-password"},
            },
            id="missing_base_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()


@pytest.mark.parametrize(
    "field,value",
    [
        ("database", "my-db"),
        ("database", "db;DROP TABLE x"),
        ("table", "opencti stream"),
        ("table", "1invalid"),
    ],
)
def test_settings_should_reject_invalid_clickhouse_identifiers(field, value):
    bad = _valid_settings()
    bad["clickhouse"][field] = value

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(bad)

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
