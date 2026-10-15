"""Tests for connector.settings (connectors-sdk configuration)."""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

VALID = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "05ff90d6-548b-40ef-983b-79044f2d2dc6",
        "name": "WhoisFreaks",
        "scope": "indicator,domain-name",
        "log_level": "info",
        "duration_period": "PT24H",
    },
    "whoisfreaks": {"api_key": "test-api-key"},
}


def _fake_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _data: Any, handler: Any) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_settings_accepts_valid_input():
    settings = _fake_settings(VALID)
    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.whoisfreaks, BaseConfigModel)
    assert isinstance(settings.to_helper_config(), dict)


@pytest.mark.parametrize(
    "settings_dict",
    [
        {},
        {**VALID, "whoisfreaks": {}},
        {**VALID, "opencti": {"url": "not-a-url", "token": "t"}},
    ],
)
def test_settings_rejects_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        _fake_settings(settings_dict)


def test_whoisfreaks_defaults():
    settings = _fake_settings(VALID)
    assert settings.whoisfreaks.feed_types == ["malware", "phishing", "spam"]
    assert settings.whoisfreaks.nrd_feed_types == [
        "nrd_gtld_with_whois",
        "nrd_cctld_with_whois",
        "nrd_gtld_without_whois",
        "nrd_cctld_without_whois",
    ]
    assert settings.whoisfreaks.page_limit == 5000
    assert settings.whoisfreaks.nrd_timeout == 180
    assert settings.whoisfreaks.threat_timeout == 180
    assert settings.whoisfreaks.max_retries == 5
    assert settings.whoisfreaks.create_indicators_for_nrd is False
    assert isinstance(settings.whoisfreaks.import_since, datetime)
    expected_floor = datetime.now(timezone.utc) - timedelta(days=1)
    assert abs((settings.whoisfreaks.import_since - expected_floor).total_seconds()) < 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("feed_types", "malware,not-a-feed"),
        ("nrd_feed_types", "nrd_gtld_with_whois,invalid-feed"),
    ],
)
def test_whoisfreaks_rejects_unsupported_feed_types(field, value):
    settings_dict = {
        **VALID,
        "whoisfreaks": {"api_key": "test-api-key", field: value},
    }

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        _fake_settings(settings_dict)
