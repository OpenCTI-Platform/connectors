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
    "google_secops_rules": {
        "project_id": "soc-project",
        "project_region": "europe",
        "project_instance": "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6",
        "client_email": "opencti@soc-project.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\\n",
    },
}


class FakeCredentials:
    """Service account credentials handing out ``tokens`` one per refresh."""

    def __init__(self, *tokens: str, error: Exception | None = None) -> None:
        self._tokens = list(tokens) or ["token-1"]
        self._error = error
        self.token: str | None = None
        self.refreshes = 0

    @property
    def valid(self) -> bool:
        return self.token is not None

    def refresh(self, request: Any) -> None:
        self.refreshes += 1
        if self._error is not None:
            raise self._error
        self.token = self._tokens.pop(0)


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
