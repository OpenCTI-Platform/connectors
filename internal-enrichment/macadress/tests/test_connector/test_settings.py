"""Settings (config-model) tests for the macadress.com enrichment connector."""

from connector.settings import InternalEnrichmentConnectorConfig, MacadressConfig
from pydantic import SecretStr


def test_api_key_is_secret():
    cfg = MacadressConfig(api_key="mk_super_secret")
    assert isinstance(cfg.api_key, SecretStr)
    assert cfg.api_key.get_secret_value() == "mk_super_secret"
    assert "mk_super_secret" not in repr(cfg)


def test_defaults():
    cfg = MacadressConfig(api_key="mk_x")
    assert str(cfg.api_base_url).rstrip("/") == "https://api.macadress.com"
    assert cfg.max_tlp == "TLP:AMBER"
    assert cfg.default_score == 30
    assert cfg.create_note is True
    assert cfg.create_vendor_identity is True


def test_scope_parses_comma_string():
    # ListFromString turns "a,b" into ["a", "b"]; `id` is required by the SDK
    # base config (supplied at runtime via CONNECTOR_ID).
    cfg = InternalEnrichmentConnectorConfig(
        id="3dc00c31-f8f4-470b-bfb4-35a11ccd5c75", scope="Mac-Addr, IPv4-Addr"
    )
    assert cfg.scope == ["Mac-Addr", "IPv4-Addr"]
