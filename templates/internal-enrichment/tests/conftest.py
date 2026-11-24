"""Pytest fixtures shared by all the tests.

All the test files in `tests/` can use these fixtures without importing them.
"""

import os
import sys
from typing import Any

import pytest

# Let test files import "connector"/"template_client" the same way `main.py` does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402
from connectors_sdk import EnrichmentMessage  # noqa: E402
from connectors_sdk.models import IPV4Address  # noqa: E402


class TestConnectorSettings(ConnectorSettings):
    """Valid `ConnectorSettings` for the tests.

    They do not read environment variables or `config.yml`: `_load_config_dict`
    returns fixed values.
    """

    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "IPv4-Addr",
                    "log_level": "error",
                },
                "template": {
                    "api_key": "test-api-key",
                },
            }
        )


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()


@pytest.fixture
def ipv4_message() -> EnrichmentMessage:
    """An enrichment message for the IPv4 address `1.2.3.4`.

    The connector gives messages like this one to the processors.

    TODO:
        - [ ] Add one fixture per entity type your processors enrich.
    """
    stix_entity = IPV4Address(value="1.2.3.4").to_stix2_object()
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {
                "id": "opencti-internal-id",
                "entity_type": "IPv4-Addr",
                "objectMarking": [],
            },
            "stix_entity": dict(stix_entity),
            "stix_objects": [dict(stix_entity)],
            "from_playbook": False,
        }
    )
