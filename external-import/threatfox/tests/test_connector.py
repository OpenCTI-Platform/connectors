"""Tests for the ThreatFox connector configuration loader.

Tests verify that the Pydantic-based ConfigLoader can be populated from
environment variables and that default values are applied correctly.
"""

import pytest

from src.models.configs.config_loader import ConfigLoader
from src.models.configs.threatfox_configs import _ConfigLoaderThreatFox


class TestThreatFoxConfigDefaults:
    """Tests for ThreatFox-specific config default values."""

    def test_default_csv_url(self):
        cfg = _ConfigLoaderThreatFox()
        assert cfg.csv_url == "https://threatfox.abuse.ch/export/csv/recent/"

    def test_default_import_offline_is_true(self):
        cfg = _ConfigLoaderThreatFox()
        assert cfg.import_offline is True

    def test_default_create_indicators_is_true(self):
        cfg = _ConfigLoaderThreatFox()
        assert cfg.create_indicators is True

    def test_default_score_is_50(self):
        cfg = _ConfigLoaderThreatFox()
        assert cfg.default_x_opencti_score == 50

    def test_default_type_specific_scores_are_none(self):
        cfg = _ConfigLoaderThreatFox()
        assert cfg.x_opencti_score_ip is None
        assert cfg.x_opencti_score_domain is None
        assert cfg.x_opencti_score_url is None
        assert cfg.x_opencti_score_hash is None

    def test_default_ioc_to_import(self):
        cfg = _ConfigLoaderThreatFox()
        assert cfg.ioc_to_import == "all_types"


class TestThreatFoxConfigFromEnv:
    """Tests that env vars override defaults correctly."""

    def test_csv_url_from_env(self, monkeypatch):
        monkeypatch.setenv("CSV_URL", "https://custom.example.com/feed.csv")
        cfg = _ConfigLoaderThreatFox()
        assert cfg.csv_url == "https://custom.example.com/feed.csv"

    def test_score_override_from_env(self, monkeypatch):
        monkeypatch.setenv("DEFAULT_X_OPENCTI_SCORE", "80")
        cfg = _ConfigLoaderThreatFox()
        assert cfg.default_x_opencti_score == 80

    def test_type_specific_score_from_env(self, monkeypatch):
        monkeypatch.setenv("X_OPENCTI_SCORE_IP", "90")
        cfg = _ConfigLoaderThreatFox()
        assert cfg.x_opencti_score_ip == 90

    def test_create_indicators_false_from_env(self, monkeypatch):
        monkeypatch.setenv("CREATE_INDICATORS", "false")
        cfg = _ConfigLoaderThreatFox()
        assert cfg.create_indicators is False


class TestConfigLoaderStructure:
    """Tests for the top-level ConfigLoader composition."""

    def test_config_loader_has_opencti_section(self, minimal_env):
        cfg = ConfigLoader()
        assert cfg.opencti is not None

    def test_config_loader_has_connector_section(self, minimal_env):
        cfg = ConfigLoader()
        assert cfg.connector is not None

    def test_config_loader_has_threatfox_section(self, minimal_env):
        cfg = ConfigLoader()
        assert cfg.threatfox is not None

    def test_opencti_url_from_env(self, minimal_env):
        cfg = ConfigLoader()
        assert "localhost" in str(cfg.opencti.url)

    def test_connector_name_default(self, minimal_env):
        cfg = ConfigLoader()
        assert cfg.connector.name == "Abuse.ch | ThreatFox"
