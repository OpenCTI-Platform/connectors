"""Settings (config-model) tests for the Metras Enrichment connector."""

from connector.settings import InternalEnrichmentConnectorConfig, MetrasConfig
from connectors_sdk.models.enums import TLPLevel
from pydantic import SecretStr


def test_api_key_is_secret():
    cfg = MetrasConfig(api_key="super-secret-key")
    assert isinstance(cfg.api_key, SecretStr)
    assert cfg.api_key.get_secret_value() == "super-secret-key"
    assert "super-secret-key" not in repr(cfg)


def test_max_tlp_default_is_tlplevel():
    cfg = MetrasConfig(api_key="k")
    assert cfg.max_tlp is TLPLevel.AMBER_STRICT
    assert cfg.max_tlp.value == "amber+strict"


def test_scope_parses_comma_string():
    # ListFromString turns "A,B" into ["A","B"]. `id` is required by the SDK base
    # config (supplied at runtime via CONNECTOR_ID).
    cfg = InternalEnrichmentConnectorConfig(
        id="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", scope="IPv4-Addr, StixFile"
    )
    assert cfg.scope == ["IPv4-Addr", "StixFile"]
