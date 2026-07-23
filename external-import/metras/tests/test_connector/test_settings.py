"""Settings (config-model) tests for the Metras Feed connector."""

from connector.settings import MetrasConfig
from pydantic import SecretStr


def test_api_key_is_secret():
    cfg = MetrasConfig(api_key="super-secret-key")
    assert isinstance(cfg.api_key, SecretStr)
    assert cfg.api_key.get_secret_value() == "super-secret-key"
    # The secret must not appear in the repr / str.
    assert "super-secret-key" not in repr(cfg)


def test_feed_defaults():
    cfg = MetrasConfig(api_key="k")
    assert cfg.verify_ssl is True
    assert cfg.import_alerts and cfg.import_binaries and cfg.import_endpoints
    assert cfg.binary_malicious_only is True
    assert cfg.page_size == 50
    assert cfg.tlp_level == "amber"
