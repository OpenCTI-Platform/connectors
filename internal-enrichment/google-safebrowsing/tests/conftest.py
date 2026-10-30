import os
import sys
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings, SafeBrowsingConnector
from pycti import OpenCTIConnectorHelper

BASE_CONFIG = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Google Safe Browsing",
        "scope": "Url,Domain-Name,Hostname",
        "log_level": "error",
        "auto": True,
    },
}


@pytest.fixture
def make_settings():
    """Build a `ConnectorSettings` from a dict instead of env/config vars."""

    def _make_settings(
        safe_browsing: dict[str, Any] | None = None, **extra_sections: dict[str, Any]
    ) -> ConnectorSettings:
        config = deepcopy(BASE_CONFIG)
        config["safe_browsing"] = (
            {"api_key": "k"} if safe_browsing is None else safe_browsing
        )
        config.update(extra_sections)

        class StubConnectorSettings(ConnectorSettings):
            @classmethod
            def _load_config_dict(cls, _, handler) -> dict[str, Any]:
                return handler(deepcopy(config))

        return StubConnectorSettings()

    return _make_settings


@pytest.fixture
def make_connector(make_settings):
    """Build a `SafeBrowsingConnector` with a mocked OpenCTI helper (no real connection)."""

    def _make_connector(
        safe_browsing: dict[str, Any] | None = None, **extra_sections: dict[str, Any]
    ) -> SafeBrowsingConnector:
        helper = MagicMock()
        helper.connect_scope = "Url,Domain-Name,Hostname"
        helper.check_max_tlp.side_effect = OpenCTIConnectorHelper.check_max_tlp
        return SafeBrowsingConnector(
            config=make_settings(safe_browsing, **extra_sections), helper=helper
        )

    return _make_connector


@pytest.fixture
def connector(make_connector) -> SafeBrowsingConnector:
    """A `SafeBrowsingConnector` with the default test configuration."""
    return make_connector()
