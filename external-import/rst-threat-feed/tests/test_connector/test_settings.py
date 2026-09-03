from typing import Any

import pytest
from connectors_sdk import ConfigValidationError

from connector import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Feed",
                    "scope": "application/json",
                    "log_level": "error",
                    "duration_period": "PT24H",
                },
                "rst_threat_feed": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "scope": "application/json"},
                "rst_threat_feed": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict: dict[str, Any]):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.opencti is not None
    assert settings.connector is not None
    assert settings.rst_threat_feed is not None


def test_settings_migrates_hyphen_namespace_and_legacy_interval():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "scope": "application/json",
                    },
                    "rst-threat-feed": {
                        "baseurl": "http://test.com",
                        "apikey": "test-api-key",
                        "interval": 3600,
                        "create_mitre_ttp": True,
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.rst_threat_feed.apikey == "test-api-key"
    assert settings.rst_threat_feed.create_mitre_ttps is True
    assert settings.connector.duration_period.total_seconds() == 3600


def test_settings_requires_api_key():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id", "scope": "application/json"},
                    "rst_threat_feed": {"baseurl": "http://test.com", "apikey": ""},
                }
            )

    with pytest.raises((ConfigValidationError, ValueError)):
        FakeConnectorSettings()
