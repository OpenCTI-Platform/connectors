from typing import Any, Self

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
            "name": "Redpanda",
            "scope": "redpanda",
            "log_level": "error",
            "live_stream_id": "live",
        },
        "redpanda": {
            "http_proxy_url": "http://redpanda:8082",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.redpanda, BaseConfigModel) is True


def test_settings_should_apply_redpanda_defaults():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert settings.redpanda.topic == "opencti"
    assert settings.redpanda.ssl_verify is True


@pytest.mark.parametrize("topic", ["opencti", "opencti.events", "opencti_events-1"])
def test_settings_should_accept_valid_topic(topic):
    config = _valid_settings()
    config["redpanda"]["topic"] = topic

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(config)

    settings = FakeConnectorSettings()

    assert settings.redpanda.topic == topic


@pytest.mark.parametrize("topic", ["bad topic", "topic/with/slash", "", ".", ".."])
def test_settings_should_reject_invalid_topic(topic):
    config = _valid_settings()
    config["redpanda"]["topic"] = topic

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(config)

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "redpanda",
                    "live_stream_id": "live",
                },
                "redpanda": {},
            },
            id="missing_http_proxy_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
