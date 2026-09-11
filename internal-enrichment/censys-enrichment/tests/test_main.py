"""Tests for the Censys Enrichment connector bootstrap (pycti helper instantiation)."""

from typing import Any
from unittest.mock import MagicMock

import pytest
from censys_enrichment.settings import ConfigLoader
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConfigLoader(ConfigLoader):
    """Bypass file/env loading with a fully-specified fake config dict."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469",
                    "name": "Censys Enrichment",
                    "scope": "IPv4-Addr,IPv6-Addr",
                    "log_level": "error",
                    "auto": True,
                },
                "censys_enrichment": {
                    "organisation_id": "test-org-id",
                    "token": "test-token",
                    "max_tlp": "TLP:AMBER",
                },
            }
        )


def test_config_loader_is_instantiated():
    cfg = StubConfigLoader()
    assert isinstance(cfg, ConfigLoader)
    assert isinstance(cfg.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    cfg = StubConfigLoader()
    helper = OpenCTIConnectorHelper(config=cfg.to_helper_config())
    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
