"""Tests for the connector settings (connectors-sdk BaseConnectorSettings)."""

from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

OPENCTI = {"url": "http://localhost:8080", "token": "test-token"}


def make_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of the environment or `config.yml`."""

    class StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return StubSettings()


def test_minimal_settings_use_the_defaults():
    settings = make_settings({"opencti": OPENCTI, "connector": {"id": "connector-id"}})

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.netapi, BaseConfigModel)
    assert settings.connector.name == "NetAPI"
    assert settings.connector.scope == ["Domain-Name", "Hostname", "IPv4-Addr", "Url"]
    assert settings.connector.auto is False
    assert settings.connector.max_tlp == "amber"
    assert settings.netapi.api_token is None
    assert str(settings.netapi.api_base_url) == "https://netapi.com/api-json/"
    assert settings.netapi.timeout == 30
    assert settings.netapi.include_rank is True
    assert settings.netapi.update_score is False
    assert settings.netapi.score == 80
    assert settings.netapi.tlp_level == "clear"


def test_full_settings_are_accepted():
    settings = make_settings(
        {
            "opencti": OPENCTI,
            "connector": {
                "id": "connector-id",
                "name": "NetAPI test",
                "scope": "Domain-Name, IPv4-Addr",
                "log_level": "info",
                "auto": True,
                "max_tlp": "TLP:CLEAR",
            },
            "netapi": {
                "api_token": "secret-token",
                "api_base_url": "https://staging.example.test/api-json/",
                "timeout": 5,
                "include_rank": False,
                "update_score": True,
                "score": 95,
                "tlp_level": "green",
            },
        }
    )

    assert settings.connector.scope == ["Domain-Name", "IPv4-Addr"]
    assert settings.connector.max_tlp == "clear"
    assert settings.netapi.api_token.get_secret_value() == "secret-token"
    assert settings.netapi.score == 95
    assert settings.to_helper_config()["connector"]["scope"] == "Domain-Name,IPv4-Addr"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "t"},
                "connector": {},
            },
            id="invalid_opencti_url",
        ),
        pytest.param(
            {"opencti": OPENCTI, "connector": {"scope": "Email-Addr"}},
            id="unsupported_scope",
        ),
        pytest.param(
            {"opencti": OPENCTI, "connector": {}, "netapi": {"score": 101}},
            id="score_above_100",
        ),
        pytest.param(
            {"opencti": OPENCTI, "connector": {}, "netapi": {"tlp_level": "purple"}},
            id="unknown_tlp_level",
        ),
    ],
)
def test_invalid_settings_are_refused(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        make_settings(settings_dict)
    assert "Error validating configuration" in str(err)
