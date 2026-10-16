"""Shared pytest fixtures."""

import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402

BASE_CONFIG: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "test-id", "log_level": "error"},
    "splunk_saved_searches": {
        "api_url": "https://splunk.example.com:8089",
        "token": "splunk-token",
    },
}

SCHEMA_WITH_DEPLOYED_ON = {
    "data": {
        "schemaRelationsTypesMapping": [
            {"key": "Indicator_AttackPattern", "values": ["indicates"]},
            {
                "key": "Indicator_SecurityPlatform",
                "values": ["deployed-on", "related-to"],
            },
        ]
    }
}
SCHEMA_WITHOUT_DEPLOYED_ON = {
    "data": {
        "schemaRelationsTypesMapping": [
            {"key": "Indicator_SecurityPlatform", "values": ["related-to"]},
        ]
    }
}


def make_settings(overrides: dict[str, Any] | None = None) -> ConnectorSettings:
    """Build settings from ``BASE_CONFIG`` merged with ``overrides``."""
    config = {section: dict(values) for section, values in BASE_CONFIG.items()}
    for section, values in (overrides or {}).items():
        config.setdefault(section, {}).update(values)

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(config)

    return FakeConnectorSettings()


@pytest.fixture
def helper() -> MagicMock:
    """An ``OpenCTIConnectorHelper`` whose platform defines ``deployed-on``."""
    fake = MagicMock()
    fake.api.query.return_value = SCHEMA_WITH_DEPLOYED_ON
    fake.api.attack_pattern.list.return_value = []
    fake.api.indicator.list.return_value = []
    return fake
