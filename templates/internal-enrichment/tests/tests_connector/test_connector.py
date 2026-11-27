"""Tests of the connector created in `src/main.py`.

When it is created, `InternalEnrichmentConnector` checks that a processor
handles each entity type of the scope. These tests check that the scope and
the processors match. Creating the connector does not connect to OpenCTI:
only `start()` does.

TODO:
    - [ ] Give the connector the same processors as in `src/main.py`.
"""

from typing import Any

import pytest
from connector import ConnectorSettings
from connector.enrichment_processors import IPv4Processor
from connectors_sdk import ConfigValidationError, InternalEnrichmentConnector


def build_settings(connector_config: dict[str, Any]) -> ConnectorSettings:
    """Build valid settings with the given `connector` section."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test"},
                    "connector": connector_config,
                    "template": {"api_key": "test-api-key"},
                }
            )

    return FakeConnectorSettings()


def test_connector_should_accept_the_default_scope():
    """Test that the processors handle every entity type of the default scope."""
    # Given: settings with the default scope
    settings = build_settings({})

    # When: the connector is created with the processors of `main.py`
    connector = InternalEnrichmentConnector(
        settings=settings,
        enrichment_processors=[IPv4Processor()],
    )

    # Then: it is created
    assert connector.settings == settings


def test_connector_should_refuse_a_scope_without_processor():
    """Test that a scope type that no processor handles stops the connector."""
    # Given: a scope with an entity type that no processor handles
    settings = build_settings({"scope": "IPv4-Addr,Domain-Name"})

    # When: the connector is created
    # Then: it raises
    with pytest.raises(ConfigValidationError):
        InternalEnrichmentConnector(
            settings=settings,
            enrichment_processors=[IPv4Processor()],
        )
