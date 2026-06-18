import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, Any]:
    """Load a JSON fixture from the tests/fixtures directory."""
    with (FIXTURES_DIR / name).open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock heavy OpenCTIConnectorHelper dependencies to avoid external API calls."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


@pytest.fixture
def make_stub_connector_settings():
    """Factory to create connector settings with optional recorded_future_asi overrides."""

    def _make(**recorded_future_asi_overrides: Any) -> ConnectorSettings:
        recorded_future_asi_config = {
            "api_base_url": "https://api.securitytrails.com/v2",
            "api_v1_base_url": "https://api.securitytrails.com/v1",
            "api_key": "test-api-key",
            "project_id": "test-project-id",
            "tlp_level": "amber+strict",
            "portal_base_url": "https://portal.example.com",
            "page_limit": 100,
        }
        recorded_future_asi_config.update(recorded_future_asi_overrides)

        class StubConnectorSettings(ConnectorSettings):
            @classmethod
            def _load_config_dict(cls, _, handler) -> dict[str, Any]:
                return handler(
                    {
                        "opencti": {
                            "url": "http://localhost:8080",
                            "token": "test-token",
                        },
                        "connector": {
                            "id": "connector-id",
                            "name": "Test Connector",
                            "scope": "incident",
                            "log_level": "error",
                            "duration_period": "PT5M",
                        },
                        "recorded_future_asi": recorded_future_asi_config,
                    }
                )

        return StubConnectorSettings()

    return _make


@pytest.fixture
def stub_connector_settings(make_stub_connector_settings) -> ConnectorSettings:
    """Return connector settings backed by a fixed in-memory config dict."""
    return make_stub_connector_settings()


@pytest.fixture
def opencti_helper(mock_opencti_connector_helper, stub_connector_settings):
    """Instantiate a mocked OpenCTIConnectorHelper from stub settings."""
    return OpenCTIConnectorHelper(config=stub_connector_settings.to_helper_config())


@pytest.fixture
def exposures_list_page() -> dict[str, Any]:
    """First paginated exposures list API response."""
    return load_fixture("exposures_list_page.json")


@pytest.fixture
def exposures_list_page_last() -> dict[str, Any]:
    """Final paginated exposures list API response."""
    return load_fixture("exposures_list_page_last.json")


@pytest.fixture
def all_exposure_items(
    exposures_list_page, exposures_list_page_last
) -> list[dict[str, Any]]:
    """Flattened exposure items from all fixture pages."""
    return exposures_list_page["data"] + exposures_list_page_last["data"]


@pytest.fixture
def exposure_assets_page() -> dict[str, Any]:
    """First paginated exposure assets API response."""
    return load_fixture("exposure_assets_page.json")


@pytest.fixture
def exposure_assets_page_last() -> dict[str, Any]:
    """Final paginated exposure assets API response."""
    return load_fixture("exposure_assets_page_last.json")


@pytest.fixture
def all_exposure_assets(
    exposure_assets_page, exposure_assets_page_last
) -> dict[str, Any]:
    """Aggregated exposure assets from all fixture pages."""
    return {
        "signature": exposure_assets_page_last["data"]["signature"],
        "asset_exposures": (
            exposure_assets_page["data"]["asset_exposures"]
            + exposure_assets_page_last["data"]["asset_exposures"]
        ),
    }


@pytest.fixture
def risk_history_activity() -> dict[str, Any]:
    """Exposure history activity API response with added and removed rules."""
    return load_fixture("risk_history_activity.json")
