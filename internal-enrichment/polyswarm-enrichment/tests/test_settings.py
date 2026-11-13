"""Tests for the PolySwarm enrichment connector settings."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from connectors_sdk import ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from polyswarm_enrichment.settings import ConnectorSettings


def _settings_from(polyswarm: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a fake config dict instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "polyswarm": {"api_key": "test-key", **polyswarm},
                }
            )

    return FakeConnectorSettings()


def test_settings_should_default_connector_max_tlp_to_red():
    # Given/When: No max TLP is configured
    settings = _settings_from({})

    # Then: Every entity is enriched, as with the former empty default
    assert settings.connector.max_tlp == TLPLevel.RED


def test_settings_should_migrate_deprecated_polyswarm_max_tlp_to_connector_max_tlp():
    # Given/When: The deprecated polyswarm.max_tlp is set
    with pytest.warns(UserWarning, match="polyswarm.max_tlp"):
        settings = _settings_from({"max_tlp": "TLP:GREEN"})

    # Then: The value is used as connector.max_tlp
    assert settings.connector.max_tlp == TLPLevel.GREEN


def test_settings_should_migrate_empty_deprecated_polyswarm_max_tlp_to_red():
    # Given/When: The deprecated polyswarm.max_tlp is set to "" (former "no limit")
    with pytest.warns(UserWarning, match="polyswarm.max_tlp"):
        settings = _settings_from({"max_tlp": ""})

    # Then: It still means no limit
    assert settings.connector.max_tlp == TLPLevel.RED


def test_settings_should_default_network_lookup_settings():
    # Given/When: No network lookup setting is configured
    settings = _settings_from({})

    # Then: Related files are capped at 10 and indicators need 2 detections
    assert settings.polyswarm.network_related_files_max == 10
    assert settings.polyswarm.network_indicator_min_detections == 2


def test_settings_should_default_scope_to_files_and_network_observables():
    # Given/When: No scope is configured
    settings = _settings_from({})

    # Then: Hashes and URL, domain and IP observables are all in scope
    assert settings.connector.scope == [
        "StixFile",
        "Artifact",
        "Url",
        "Domain-Name",
        "IPv4-Addr",
        "IPv6-Addr",
    ]


def test_settings_should_read_network_lookup_settings_from_env(monkeypatch):
    # Given: The connector is configured through environment variables
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "connector-id")
    monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")
    monkeypatch.setenv("POLYSWARM_NETWORK_RELATED_FILES_MAX", "0")
    monkeypatch.setenv("POLYSWARM_NETWORK_INDICATOR_MIN_DETECTIONS", "3")

    # When: Settings are loaded
    settings = ConnectorSettings()

    # Then: The env values are used (0 disables related files)
    assert settings.polyswarm.network_related_files_max == 0
    assert settings.polyswarm.network_indicator_min_detections == 3


def test_settings_should_reject_negative_related_files_max():
    # Given/When/Then: A negative cap is a configuration error
    with pytest.raises(ConfigValidationError):
        _settings_from({"network_related_files_max": -1})


def test_settings_should_default_connector_auto_to_false():
    # Given/When: No auto setting is configured
    settings = _settings_from({})

    # Then: Enrichment is manual, nothing is sent to PolySwarm unasked
    assert settings.connector.auto is False


def test_samples_should_keep_connector_auto_false():
    # Given: The sample config and docker-compose shipped with the connector
    root = Path(__file__).resolve().parent.parent
    config_sample = yaml.safe_load((root / "config.yml.sample").read_text())
    compose = (root / "docker-compose.yml").read_text()

    # Then: Neither sample turns on auto-enrichment
    assert config_sample["connector"]["auto"] is False
    assert "CONNECTOR_AUTO=true" not in compose


def test_settings_should_read_polykg_url_from_polyswarm_prefixed_env(monkeypatch):
    # Given: The documented variable, and the old unprefixed name that is not read
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
    monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")
    monkeypatch.setenv("POLYSWARM_POLYKG_API_URL", "http://polykg:4141")
    monkeypatch.setenv("POLYKG_API_URL", "http://ignored:4141")
    monkeypatch.setenv("POLYSWARM_COMMUNITY", "private")

    # When
    settings = ConnectorSettings()

    # Then: Only the POLYSWARM_ prefixed names are used, as the README documents
    assert settings.polyswarm.polykg_api_url == "http://polykg:4141"
    assert settings.polyswarm.community == "private"


def test_settings_should_strip_url_query_strings_by_default():
    # Given/When: Nothing is configured
    settings = _settings_from({})

    # Then: URL query strings are not sent unless opted in
    assert settings.polyswarm.network_url_send_query is False


def test_settings_should_accept_url_query_opt_in():
    settings = _settings_from({"network_url_send_query": True})
    assert settings.polyswarm.network_url_send_query is True


def test_settings_should_default_quota_warn_below_to_100():
    assert _settings_from({}).polyswarm.quota_warn_below == 100


def test_settings_should_accept_zero_to_turn_quota_warnings_off():
    assert _settings_from({"quota_warn_below": 0}).polyswarm.quota_warn_below == 0


def test_settings_should_reject_a_negative_quota_warn_below():
    with pytest.raises(ConfigValidationError):
        _settings_from({"quota_warn_below": -1})
