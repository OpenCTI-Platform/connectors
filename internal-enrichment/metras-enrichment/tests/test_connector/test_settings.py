"""Settings (config-model) tests for the Metras Enrichment connector."""

from typing import Any

import pytest
from connector.settings import (
    ConnectorSettings,
    InternalEnrichmentConnectorConfig,
    MetrasConfig,
)
from pydantic import SecretStr


def test_api_key_is_secret():
    cfg = MetrasConfig(api_key="super-secret-key")
    assert isinstance(cfg.api_key, SecretStr)
    assert cfg.api_key.get_secret_value() == "super-secret-key"
    assert "super-secret-key" not in repr(cfg)


def test_connector_max_tlp_default_is_amber_strict():
    # The connector keeps its historical default (amber+strict) instead of the
    # SDK default (TLP:AMBER).
    cfg = InternalEnrichmentConnectorConfig(id="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
    assert cfg.max_tlp == "TLP:AMBER+STRICT"


def test_deprecated_metras_max_tlp_is_migrated_to_connector_max_tlp():
    # The deprecated `metras.max_tlp` (`METRAS_MAX_TLP`) still works, in its
    # historical lowercase form, and is moved to `connector.max_tlp`
    # (`CONNECTOR_MAX_TLP`).
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"},
                    "metras": {"api_key": "k", "max_tlp": "red"},
                }
            )

    with pytest.warns(UserWarning, match="metras.max_tlp"):
        settings = FakeConnectorSettings()

    assert settings.connector.max_tlp == "TLP:RED"


def test_scope_parses_comma_string():
    # ListFromString turns "A,B" into ["A","B"]. `id` is required by the SDK base
    # config (supplied at runtime via CONNECTOR_ID).
    cfg = InternalEnrichmentConnectorConfig(
        id="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", scope="IPv4-Addr, StixFile"
    )
    assert cfg.scope == ["IPv4-Addr", "StixFile"]
