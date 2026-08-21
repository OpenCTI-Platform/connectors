from __future__ import annotations

from connector.logging_config import _DEFAULT_LOG_MAX_BYTES, FileLoggingConfig
from connector.settings import ConfigConnector


def _inst() -> ConfigConnector:
    """Bypass __init__ — return a bare instance with no attributes set
    so tests can drive the resolution path explicitly."""
    return ConfigConnector.__new__(ConfigConnector)


# --- get_collection_settings -------------------------------------------------


class TestGetCollectionSettings:
    def test_known_attribute(self):
        inst = _inst()
        inst.ti_api_collections_apt_threat_ttl = 1460
        assert inst.get_collection_settings("apt_threat", "ttl") == 1460

    def test_missing_returns_none(self):
        inst = _inst()
        # No matching attribute → None.
        assert inst.get_collection_settings("nope_collection", "ttl") is None

    def test_returns_string_value(self):
        inst = _inst()
        inst.ti_api_collections_apt_threat_enable = "true"
        assert inst.get_collection_settings("apt_threat", "enable") == "true"


# --- get_extra_settings_by_name ---------------------------------------------


class TestGetExtraSettingsByName:
    def test_known_attribute(self):
        inst = _inst()
        inst.ti_api_extra_settings_enable_statement_marking = True
        assert inst.get_extra_settings_by_name("enable_statement_marking") is True

    def test_missing_returns_none(self):
        inst = _inst()
        assert inst.get_extra_settings_by_name("not_a_setting") is None


# --- get_setting (collection → extra fallback) -----------------------------


class TestGetSetting:
    def test_collection_value_wins(self):
        inst = _inst()
        inst.ti_api_collections_apt_threat_ttl = 1460
        inst.ti_api_extra_settings_ttl = 9999
        # Collection key resolved first.
        assert inst.get_setting("apt/threat", "ttl") == 1460

    def test_falls_back_to_extra(self):
        inst = _inst()
        inst.ti_api_extra_settings_intrusion_set_instead_of_threat_actor = True
        out = inst.get_setting("apt/threat", "intrusion_set_instead_of_threat_actor")
        assert out is True

    def test_default_when_neither(self):
        inst = _inst()
        # No matching attribute anywhere → user-supplied default.
        out = inst.get_setting("nope_collection", "nope_key", default="fallback")
        assert out == "fallback"

    def test_slash_in_collection_normalised(self):
        inst = _inst()
        # API uses "apt/threat" but env attribute path uses "apt_threat".
        inst.ti_api_collections_apt_threat_use_hunting_rules = "true"
        assert inst.get_setting("apt/threat", "use_hunting_rules") == "true"

    def test_empty_collection_string(self):
        inst = _inst()
        # Empty collection slug → still consults extra_settings.
        inst.ti_api_extra_settings_some_global = "v"
        out = inst.get_setting("", "some_global")
        assert out == "v"


# --- get_setting_bool -------------------------------------------------------


class TestGetSettingBool:
    def test_true_string(self):
        inst = _inst()
        inst.ti_api_collections_apt_threat_enable = "true"
        assert inst.get_setting_bool("apt/threat", "enable") is True

    def test_false_string(self):
        inst = _inst()
        inst.ti_api_collections_apt_threat_enable = "false"
        assert inst.get_setting_bool("apt/threat", "enable") is False

    def test_missing_uses_default_true(self):
        # Default is ``True``.
        inst = _inst()
        assert inst.get_setting_bool("nope", "nope") is True

    def test_missing_uses_explicit_default(self):
        inst = _inst()
        assert inst.get_setting_bool("nope", "nope", default=False) is False

    def test_bool_value_passes_through(self):
        inst = _inst()
        inst.ti_api_collections_apt_threat_enable = True
        assert inst.get_setting_bool("apt/threat", "enable") is True


# --- get_extra_settings_bool ------------------------------------------------


class TestGetExtraSettingsBool:
    def test_true(self):
        inst = _inst()
        inst.ti_api_extra_settings_x = "yes"
        assert inst.get_extra_settings_bool("x") is True

    def test_false_default(self):
        # Default is False for extra settings.
        inst = _inst()
        assert inst.get_extra_settings_bool("missing") is False

    def test_explicit_default(self):
        inst = _inst()
        assert inst.get_extra_settings_bool("missing", default=True) is True


# --- get_file_logging_config ------------------------------------------------


class TestGetFileLoggingConfig:
    def test_disabled_by_default(self):
        inst = _inst()
        cfg = inst.get_file_logging_config()
        assert isinstance(cfg, FileLoggingConfig)
        assert cfg.enabled is False

    def test_enabled_with_directory(self):
        inst = _inst()
        inst.ti_api_extra_settings_enable_file_logging = "true"
        inst.ti_api_extra_settings_log_file_dir = "/tmp/connector-logs"
        inst.ti_api_extra_settings_log_file_max_bytes = "1024"
        inst.ti_api_extra_settings_log_file_backup_count = "3"
        cfg = inst.get_file_logging_config()
        assert cfg.enabled is True
        assert cfg.directory == "/tmp/connector-logs"
        assert cfg.max_bytes == 1024
        assert cfg.backup_count == 3

    def test_invalid_max_bytes_falls_back_to_default(self):
        inst = _inst()
        inst.ti_api_extra_settings_enable_file_logging = "true"
        inst.ti_api_extra_settings_log_file_max_bytes = "not-an-int"
        cfg = inst.get_file_logging_config()
        # ``_to_int`` falls back to the exact module default, not just any
        # positive number.
        assert cfg.max_bytes == _DEFAULT_LOG_MAX_BYTES
