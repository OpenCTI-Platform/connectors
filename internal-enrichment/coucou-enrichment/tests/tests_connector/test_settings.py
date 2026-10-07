from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import ConfigValidationError


def _fake_settings(settings_dict: dict) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        """Load `settings_dict` instead of config.yml / .env / env vars."""

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_settings_should_apply_defaults_on_minimal_input():
    settings = _fake_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {"id": "connector-id"},
        }
    )

    assert settings.connector.name == "Coucou Enrichment"
    assert settings.connector.scope == ["IPv4-Addr"]
    assert settings.connector.auto is False
    assert settings.coucou_enrichment.max_tlp_level == "amber+strict"


def test_settings_should_accept_overrides():
    settings = _fake_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {"id": "connector-id", "name": "My Coucou"},
            "coucou_enrichment": {"max_tlp_level": "red"},
        }
    )

    assert settings.connector.name == "My Coucou"
    assert settings.coucou_enrichment.max_tlp_level == "red"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {"opencti": {"url": "http://localhost:8080", "token": "test-token"}},
            id="missing_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id"},
                "coucou_enrichment": {"max_tlp_level": "purple"},
            },
            id="invalid_max_tlp_level",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError):
        _fake_settings(settings_dict)
