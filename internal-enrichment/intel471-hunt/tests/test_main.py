"""Wiring tests: the Pydantic settings must flow into the helper and connector.

These cover the manager-supported contract of `src.main.main()` — settings are
built from the environment, handed to `OpenCTIConnectorHelper` through
`to_helper_config()`, and passed on to the connector — without opening a single
connection to an OpenCTI platform.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from src.connector import HunterEnrichmentConnector
from src.settings import ConnectorSettings

REQUIRED_ENV = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "token",
    "CONNECTOR_ID": "11111111-1111-1111-1111-111111111111",
    "HUNTER_API_KEY": "secret",
}

OPTIONAL_ENV = (
    "CONNECTOR_NAME",
    "CONNECTOR_SCOPE",
    "CONNECTOR_AUTO",
    "CONNECTOR_LOG_LEVEL",
    "HUNTER_API_BASE_URL",
    "HUNTER_UI_BASE_URL",
    "HUNTER_INDEXES",
    "HUNTER_REQUEST_TIMEOUT_SECONDS",
    "HUNTER_MAX_RESULTS_PER_QUERY",
    "HUNTER_CACHE_PATH",
    "HUNTER_CACHE_TTL_HOURS",
    "HUNTER_MAX_TLP",
)


@pytest.fixture
def env(monkeypatch):
    """Start from a clean slate so the host environment can't leak in."""
    for key in list(REQUIRED_ENV) + list(OPTIONAL_ENV):
        monkeypatch.delenv(key, raising=False)
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Neutralise everything the helper does on construction (API calls,
    background ping thread, scheduler, signal hooks).

    Returns the installed mocks so tests can assert on what the helper forwarded.
    """
    module_import_path = "pycti.connector.opencti_connector_helper"
    mocks = {
        "ConnectorInfo": MagicMock(),
        "OpenCTIApiClient": MagicMock(),
        "OpenCTIConnector": MagicMock(),
        "OpenCTIMetricHandler": MagicMock(),
        "PingAlive": MagicMock(),
    }
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    for name, mock in mocks.items():
        monkeypatch.setattr(f"{module_import_path}.{name}", mock)
    return mocks


def test_connector_settings_is_instantiated(env):
    settings = ConnectorSettings()

    helper_config = settings.to_helper_config()

    assert isinstance(helper_config, dict)
    assert helper_config["opencti"]["url"].rstrip("/") == REQUIRED_ENV["OPENCTI_URL"]
    assert helper_config["opencti"]["token"] == REQUIRED_ENV["OPENCTI_TOKEN"]
    assert helper_config["connector"]["id"] == REQUIRED_ENV["CONNECTOR_ID"]
    assert helper_config["connector"]["type"] == "INTERNAL_ENRICHMENT"


def test_opencti_connector_helper_is_instantiated(env, mock_opencti_connector_helper):
    settings = ConnectorSettings()

    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(),
        playbook_compatible=True,
    )

    assert helper.connect_id == REQUIRED_ENV["CONNECTOR_ID"]
    assert helper.connect_name == "Intel 471 Hunter"
    assert helper.connect_type == "INTERNAL_ENRICHMENT"
    # Playbook compatibility is what lets this connector run as a playbook step;
    # the helper forwards it straight to the registered OpenCTIConnector.
    registration_kwargs = mock_opencti_connector_helper[
        "OpenCTIConnector"
    ].call_args.kwargs
    assert registration_kwargs["playbook_compatible"] is True


def test_connector_is_instantiated(env, mock_opencti_connector_helper):
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(),
        playbook_compatible=True,
    )

    connector = HunterEnrichmentConnector(config=settings, helper=helper)

    assert connector.config is settings
    assert connector.helper is helper
    # The Hunter settings are what actually configure the API client and cache;
    # both keep them privately, so reach in to prove the values were handed over.
    assert connector.client._base == str(settings.hunter.api_base_url)
    assert connector.client._indexes == settings.hunter.indexes
    assert connector.client._timeout == settings.hunter.request_timeout_seconds
    assert connector.client._max_results == settings.hunter.max_results_per_query
    assert connector.cache._ttl == timedelta(hours=settings.hunter.cache_ttl_hours)
    assert connector.hunter_ui_base_url == str(settings.hunter.ui_base_url)


def test_connector_settings_is_exported_from_package():
    """`mise gs` imports the model as `from src import ConnectorSettings`."""
    import src

    assert src.ConnectorSettings is ConnectorSettings
