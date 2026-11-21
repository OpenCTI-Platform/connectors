from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_settings_should_accept_minimal_input():
    settings = _settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "cyble_vision_writeback": {
                "api_token": "test-api-token",
                "import_user_ids": "import-user-id",
            },
        }
    )

    assert isinstance(settings.connector, BaseConfigModel)
    assert settings.connector.id == "db8442d4-2e03-4bcb-9d9c-7c119d50df61"
    assert settings.connector.scope == ["Incident"]
    assert settings.connector.live_stream_id == "live"
    assert settings.connector.live_stream_listen_delete is False
    assert settings.connector.live_stream_recover is False
    cfg = settings.cyble_vision_writeback
    assert cfg.api_token.get_secret_value() == "test-api-token"
    assert cfg.import_user_ids == ["import-user-id"]


def test_settings_should_honour_configured_connector_identity():
    settings = _settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {"id": "my-connector-id", "name": "My Writeback"},
            "cyble_vision_writeback": {
                "api_token": "test-api-token",
                "import_user_ids": "import-user-id",
            },
        }
    )

    helper_config = settings.to_helper_config()
    assert helper_config["connector"]["id"] == "my-connector-id"
    assert helper_config["connector"]["name"] == "My Writeback"
    assert helper_config["connector"]["type"] == "STREAM"


@pytest.mark.parametrize("recover, expected", [(False, "none"), (True, None)])
def test_live_stream_recover_reaches_the_helper(recover, expected):
    settings = _settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {"live_stream_recover": recover},
            "cyble_vision_writeback": {
                "api_token": "test-api-token",
                "import_user_ids": "import-user-id",
            },
        }
    )

    helper_config = settings.to_helper_config()
    assert helper_config["connector"]["live_stream_recover_iso_date"] == expected


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "cyble_vision_writeback": {},
            },
            "cyble_vision_writeback.api_token",
            id="missing_api_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "cyble_vision_writeback": {"api_token": "test-api-token"},
            },
            "cyble_vision_writeback.import_user_ids",
            id="missing_import_user_ids",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    with pytest.raises(ConfigValidationError) as err:
        _settings(settings_dict)

    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)
