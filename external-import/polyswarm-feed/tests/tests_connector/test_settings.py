from datetime import timedelta
from typing import Any

import pytest
from conftest import BASE_SETTINGS, make_settings
from connector import ConnectorSettings
from connector.settings import PolySwarmFeedConfig
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel


def _settings_from(config: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return FakeConnectorSettings()


def test_minimal_settings_use_contract_defaults():
    settings = _settings_from(
        {
            "opencti": BASE_SETTINGS["opencti"],
            "polyswarm": {"api_key": "key", "account_number": "000000000000"},
        }
    )

    assert isinstance(settings.polyswarm, BaseConfigModel)
    assert isinstance(settings.polyswarm, PolySwarmFeedConfig)
    assert settings.connector.name == "PolySwarm Feed"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert "Indicator" in settings.connector.scope
    polyswarm = settings.polyswarm
    assert polyswarm.api_key.get_secret_value() == "key"
    assert polyswarm.account_number == "000000000000"
    assert polyswarm.api_url == "https://api.polyswarm.network"
    assert polyswarm.feed_collections == ["trustgroup"]
    assert polyswarm.feed_backfill_days == 14
    assert polyswarm.feed_indicator_valid_days == 90
    assert polyswarm.hunting_enabled is False
    assert polyswarm.hunting_backfill_hours == 24
    assert polyswarm.hunting_indicator_valid_days == 30
    assert polyswarm.tlp_level == TLPLevel.CLEAR
    assert polyswarm.max_objects_per_run == 20000


def test_api_key_is_secret():
    settings = make_settings()
    assert "test-api-key" not in repr(settings.polyswarm)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("trustgroup", ["trustgroup"]),
        ("trustgroup,ransomware,freemium", ["trustgroup", "ransomware", "freemium"]),
        (" Ransomware , freemium ", ["ransomware", "freemium"]),
        ("trustgroup,trustgroup", ["trustgroup"]),
        (["freemium"], ["freemium"]),
    ],
)
def test_feed_collections_accept_known_roots(value, expected):
    settings = make_settings(feed_collections=value)
    assert settings.polyswarm.feed_collections == expected


@pytest.mark.parametrize("value", ["trustgroup,unknown", "14-Day Feed", "", " , "])
def test_feed_collections_reject_unknown_or_empty(value):
    with pytest.raises(ConfigValidationError) as err:
        make_settings(feed_collections=value)
    assert "polyswarm.feed_collections" in str(err.value.__cause__)


def test_api_url_trailing_slash_is_stripped():
    settings = make_settings(api_url="https://example.test/")
    assert settings.polyswarm.api_url == "https://example.test"


@pytest.mark.parametrize(
    "value",
    ["http://api.polyswarm.network", "api.polyswarm.network", "ftp://x.test", ""],
)
def test_api_url_must_be_https(value):
    with pytest.raises(ConfigValidationError) as err:
        make_settings(api_url=value)
    assert "polyswarm.api_url" in str(err.value.__cause__)
    assert "https" in str(err.value.__cause__)


def test_string_values_are_coerced():
    settings = make_settings(
        hunting_enabled="true",
        max_objects_per_run="500",
        tlp_level="amber+strict",
    )
    assert settings.polyswarm.hunting_enabled is True
    assert settings.polyswarm.max_objects_per_run == 500
    assert settings.polyswarm.tlp_level == TLPLevel.AMBER_STRICT


@pytest.mark.parametrize(
    "polyswarm, field_name",
    [
        ({"account_number": "000000000000"}, "polyswarm.api_key"),
        ({"api_key": "key"}, "polyswarm.account_number"),
        (
            {"api_key": "key", "account_number": "0", "tlp_level": "purple"},
            "polyswarm.tlp_level",
        ),
        (
            {"api_key": "key", "account_number": "0", "max_objects_per_run": 0},
            "polyswarm.max_objects_per_run",
        ),
        (
            {"api_key": "key", "account_number": "0", "feed_backfill_days": -1},
            "polyswarm.feed_backfill_days",
        ),
    ],
)
def test_invalid_settings_raise(polyswarm, field_name):
    with pytest.raises(ConfigValidationError) as err:
        _settings_from({"opencti": BASE_SETTINGS["opencti"], "polyswarm": polyswarm})

    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)
