"""Tests for the ThreatFox connector configuration loader.

Tests verify that the Pydantic-based ConfigLoader can be populated from
environment variables and that default values are applied correctly.
"""

from src.models.configs.config_loader import ConfigLoader
from src.models.configs.threatfox_configs import _ConfigLoaderThreatFox


class TestThreatFoxConfigDefaults:
    """Tests for ThreatFox-specific config default values."""

    def test_default_export_url_built_from_auth_key(self):
        cfg = _ConfigLoaderThreatFox(auth_key="test-auth-key")
        assert cfg.csv_url is None
        assert cfg.export_url == (
            "https://threatfox-api.abuse.ch/v2/files/exports/test-auth-key/recent.csv"
        )

    def test_default_import_offline_is_true(self):
        cfg = _ConfigLoaderThreatFox(auth_key="test-auth-key")
        assert cfg.import_offline is True

    def test_default_create_indicators_is_true(self):
        cfg = _ConfigLoaderThreatFox(auth_key="test-auth-key")
        assert cfg.create_indicators is True

    def test_default_score_is_50(self):
        cfg = _ConfigLoaderThreatFox(auth_key="test-auth-key")
        assert cfg.default_x_opencti_score == 50

    def test_default_type_specific_scores_are_none(self):
        cfg = _ConfigLoaderThreatFox(auth_key="test-auth-key")
        assert cfg.x_opencti_score_ip is None
        assert cfg.x_opencti_score_domain is None
        assert cfg.x_opencti_score_url is None
        assert cfg.x_opencti_score_hash is None

    def test_default_ioc_to_import(self):
        cfg = _ConfigLoaderThreatFox(auth_key="test-auth-key")
        assert cfg.ioc_to_import == "all_types"


class TestThreatFoxConfigFromEnv:
    """Tests that env vars override defaults correctly.

    The connector always instantiates `_ConfigLoaderThreatFox` nested inside
    `ConfigLoader.threatfox`, which (per `ConfigBaseSettings`'s
    `env_nested_delimiter="_"`) requires the `THREATFOX_` prefix on env vars,
    e.g. `THREATFOX_CSV_URL`. Setting bare `CSV_URL` and instantiating
    `_ConfigLoaderThreatFox()` standalone would pass even if the real,
    documented env var contract were broken, so these go through the full
    `ConfigLoader()` with prefixed names instead.
    """

    def test_csv_url_from_env(self, minimal_env, monkeypatch):
        monkeypatch.setenv("THREATFOX_CSV_URL", "https://custom.example.com/feed.csv")
        cfg = ConfigLoader()
        assert (
            cfg.threatfox.csv_url.get_secret_value()
            == "https://custom.example.com/feed.csv"
        )
        assert cfg.threatfox.export_url == "https://custom.example.com/feed.csv"

    def test_score_override_from_env(self, minimal_env, monkeypatch):
        monkeypatch.setenv("THREATFOX_DEFAULT_X_OPENCTI_SCORE", "80")
        cfg = ConfigLoader()
        assert cfg.threatfox.default_x_opencti_score == 80

    def test_type_specific_score_from_env(self, minimal_env, monkeypatch):
        monkeypatch.setenv("THREATFOX_X_OPENCTI_SCORE_IP", "90")
        cfg = ConfigLoader()
        assert cfg.threatfox.x_opencti_score_ip == 90

    def test_create_indicators_false_from_env(self, minimal_env, monkeypatch):
        monkeypatch.setenv("THREATFOX_CREATE_INDICATORS", "false")
        cfg = ConfigLoader()
        assert cfg.threatfox.create_indicators is False


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
