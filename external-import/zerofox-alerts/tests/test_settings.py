"""Tests for the ZeroFox Alerts connector settings."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from zerofox_alerts import ConnectorSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build a ConnectorSettings instance from a raw dict (bypasses env/config)."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


MINIMAL_VALID: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "zerofox_alerts": {
        "api_token": "zf-pat-token",
    },
}

FULL_VALID: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "ZeroFox Alerts",
        "scope": "zerofox-alerts",
        "log_level": "info",
        "duration_period": "PT15M",
    },
    "zerofox_alerts": {
        "api_base_url": "https://api.zerofox.com",
        "api_token": "zf-pat-token",
        "marking": "green",
        "import_start_date": "P7D",
        "alert_statuses": "open,escalated",
        "page_size": 50,
    },
}


# ---------------------------------------------------------------------------
# Valid settings
# ---------------------------------------------------------------------------


class TestValidSettings:
    """Ensure valid configurations are accepted."""

    @pytest.mark.parametrize(
        "settings_dict",
        [
            pytest.param(MINIMAL_VALID, id="minimal"),
            pytest.param(FULL_VALID, id="full"),
        ],
    )
    def test_accepts_valid_input(self, settings_dict):
        settings = _make_settings(settings_dict)

        assert isinstance(settings.opencti, BaseConfigModel)
        assert isinstance(settings.connector, BaseConfigModel)
        assert isinstance(settings.zerofox_alerts, BaseConfigModel)

    def test_defaults_applied_correctly(self):
        settings = _make_settings(MINIMAL_VALID)

        assert settings.connector.name == "ZeroFox Alerts"
        assert settings.connector.duration_period == timedelta(minutes=15)
        assert str(settings.zerofox_alerts.api_base_url) == "https://api.zerofox.com/"
        assert settings.zerofox_alerts.marking == "amber"
        assert settings.zerofox_alerts.import_start_date == timedelta(days=30)
        assert settings.zerofox_alerts.alert_statuses == [
            "open",
            "escalated",
            "investigation_completed",
        ]
        assert settings.zerofox_alerts.page_size == 100

    def test_full_settings_override_defaults(self):
        settings = _make_settings(FULL_VALID)

        assert settings.zerofox_alerts.marking == "green"
        assert settings.zerofox_alerts.import_start_date == timedelta(days=7)
        assert settings.zerofox_alerts.alert_statuses == ["open", "escalated"]
        assert settings.zerofox_alerts.page_size == 50

    def test_api_token_is_secret(self):
        settings = _make_settings(MINIMAL_VALID)

        assert settings.zerofox_alerts.api_token.get_secret_value() == "zf-pat-token"
        # SecretStr should not leak in string repr
        assert "zf-pat-token" not in repr(settings.zerofox_alerts.api_token)


# ---------------------------------------------------------------------------
# Invalid settings
# ---------------------------------------------------------------------------


class TestInvalidSettings:
    """Ensure invalid configurations raise ConfigValidationError."""

    @pytest.mark.parametrize(
        "settings_dict, field_name",
        [
            pytest.param(
                {},
                "settings",
                id="empty_dict",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080"},
                    "connector": {},
                    "zerofox_alerts": {"api_token": "tok"},
                },
                "opencti.token",
                id="missing_opencti_token",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {"id": 12345},
                    "zerofox_alerts": {"api_token": "tok"},
                },
                "connector.id",
                id="invalid_connector_id_type",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "zerofox_alerts": {},
                },
                "zerofox_alerts.api_token",
                id="missing_api_token",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "zerofox_alerts": {
                        "api_token": "tok",
                        "marking": "INVALID",
                    },
                },
                "zerofox_alerts.marking",
                id="invalid_marking",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "zerofox_alerts": {
                        "api_token": "tok",
                        "page_size": 0,
                    },
                },
                "zerofox_alerts.page_size",
                id="page_size_below_minimum",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "zerofox_alerts": {
                        "api_token": "tok",
                        "page_size": 200,
                    },
                },
                "zerofox_alerts.page_size",
                id="page_size_above_maximum",
            ),
        ],
    )
    def test_raises_on_invalid_input(self, settings_dict, field_name):
        with pytest.raises(ConfigValidationError) as err:
            _make_settings(settings_dict)
        assert "Error validating configuration" in str(err)
