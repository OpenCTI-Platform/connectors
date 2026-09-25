"""Settings (config-model) tests for the Metras Stream connector."""

from connector.settings import MetrasConfig
from pydantic import SecretStr


def test_api_key_is_secret():
    cfg = MetrasConfig(api_key="super-secret-key")
    assert isinstance(cfg.api_key, SecretStr)
    assert cfg.api_key.get_secret_value() == "super-secret-key"
    assert "super-secret-key" not in repr(cfg)


def test_stream_defaults():
    cfg = MetrasConfig(api_key="k")
    assert cfg.verify_ssl is True
    assert cfg.blocklist_action == "ALERT"
    assert cfg.blocklist_platform == "windows"
    assert cfg.blocklist_severity == "Medium"
