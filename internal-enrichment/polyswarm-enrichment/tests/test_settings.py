"""Tests for the PolySwarm enrichment connector settings."""

from typing import Any

import pytest
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
    assert settings.connector.max_tlp == "TLP:RED"


def test_settings_should_migrate_deprecated_polyswarm_max_tlp_to_connector_max_tlp():
    # Given/When: The deprecated polyswarm.max_tlp is set
    with pytest.warns(UserWarning, match="polyswarm.max_tlp"):
        settings = _settings_from({"max_tlp": "TLP:GREEN"})

    # Then: The value is used as connector.max_tlp
    assert settings.connector.max_tlp == "TLP:GREEN"


def test_settings_should_migrate_empty_deprecated_polyswarm_max_tlp_to_red():
    # Given/When: The deprecated polyswarm.max_tlp is set to "" (former "no limit")
    with pytest.warns(UserWarning, match="polyswarm.max_tlp"):
        settings = _settings_from({"max_tlp": ""})

    # Then: It still means no limit
    assert settings.connector.max_tlp == "TLP:RED"
