"""Tests for the ORKL connector settings."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from orkl import ConnectorSettings

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
    "orkl": {},
}

FULL_VALID: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "ORKL",
        "scope": "orkl",
        "log_level": "info",
        "duration_period": "P1D",
    },
    "orkl": {
        "api_base_url": "https://orkl.eu/api/v1",
        "import_start_date": "P7D",
        "tlp_level": "amber",
        "threat_actor_as_intrusion_set": False,
        "ingest_tools": True,
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
        assert isinstance(settings.orkl, BaseConfigModel)

    def test_defaults_applied_correctly(self):
        settings = _make_settings(MINIMAL_VALID)

        assert settings.connector.name == "ORKL"
        assert settings.connector.duration_period == timedelta(days=1)
        assert str(settings.orkl.api_base_url) == "https://orkl.eu/api/v1"
        assert settings.orkl.tlp_level == "clear"
        assert settings.orkl.import_start_date == timedelta(days=30)
        assert settings.orkl.threat_actor_as_intrusion_set is True
        assert settings.orkl.ingest_tools is False

    def test_full_settings_override_defaults(self):
        settings = _make_settings(FULL_VALID)

        assert settings.orkl.import_start_date == timedelta(days=7)
        assert settings.orkl.tlp_level == "amber"
        assert settings.orkl.threat_actor_as_intrusion_set is False
        assert settings.orkl.ingest_tools is True


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
                    "orkl": {},
                },
                "opencti.token",
                id="missing_opencti_token",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {"id": 12345},
                    "orkl": {},
                },
                "connector.id",
                id="invalid_connector_id_type",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "orkl": {"tlp_level": "INVALID"},
                },
                "orkl.tlp_level",
                id="invalid_tlp_level",
            ),
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "orkl": {"threat_actor_as_intrusion_set": "not-a-bool"},
                },
                "orkl.threat_actor_as_intrusion_set",
                id="invalid_threat_actor_as_intrusion_set",
            ),
        ],
    )
    def test_raises_on_invalid_input(self, settings_dict, field_name):
        with pytest.raises(ConfigValidationError) as err:
            _make_settings(settings_dict)
        assert "Error validating configuration" in str(err)
