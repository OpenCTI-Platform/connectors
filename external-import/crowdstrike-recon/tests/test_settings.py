from datetime import timedelta
from typing import Any

from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel


def _make_settings(settings_dict):
    """Build ConnectorSettings from a fake config dict (no env/config.yml)."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


_BASE = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "CrowdStrike Recon",
        "scope": "crowdstrike-recon",
        "log_level": "error",
        "duration_period": "PT1H",
    },
}


def test_settings_accepts_valid_input():
    settings_dict = {
        **_BASE,
        "crowdstrike_recon": {
            "api_base_url": "https://api.crowdstrike.com",
            "client_id": "cid",
            "client_secret": "secret",
            "tlp_level": "amber+strict",
            "import_start_date": "P10D",
            "filter_topic": "SA_BRAND",
        },
    }

    settings = _make_settings(settings_dict)

    assert isinstance(settings.crowdstrike_recon, BaseConfigModel)
    assert settings.crowdstrike_recon.client_id == "cid"
    assert settings.crowdstrike_recon.tlp_level == "amber+strict"
    assert settings.crowdstrike_recon.import_start_date == timedelta(days=10)
    assert settings.crowdstrike_recon.filter_topic == "SA_BRAND"


def test_settings_applies_defaults():
    settings_dict = {
        **_BASE,
        "crowdstrike_recon": {
            "api_base_url": "https://api.crowdstrike.com",
            "client_id": "cid",
            "client_secret": "secret",
        },
    }

    settings = _make_settings(settings_dict)

    assert settings.crowdstrike_recon.tlp_level == "amber+strict"
    assert settings.crowdstrike_recon.import_start_date == timedelta(days=10)
    assert settings.crowdstrike_recon.filter_topic == ""
    assert settings.crowdstrike_recon.filter_type == ""
    assert settings.crowdstrike_recon.filter_priority == ""
