"""Shared test fixtures for the Zetalytics DNS connector tests."""

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub the zetalytics package at module level so that importing
# zetanalytics_dns.client never triggers a real network call.
# This must run before any test module imports zetanalytics_dns.*, which is
# why it is at module scope in conftest rather than inside a fixture.
# ---------------------------------------------------------------------------
_zetalytics_stub = MagicMock()
sys.modules.setdefault("zetalytics", _zetalytics_stub)


@pytest.fixture
def mock_opencti_helper(monkeypatch):
    """Mock the heavy OpenCTI dependencies to avoid real API calls."""
    module = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module}.PingAlive", MagicMock())


@pytest.fixture
def stub_config_dict() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "00000000-0000-4000-8000-000000000101",
            "name": "Zetalytics DNS - Test",
            "scope": "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr",
            "log_level": "error",
            "auto": False,
        },
        "zetalytics": {
            "token": "test-zetalytics-token",
            "mode": "manual",
            "max_results": 100,
            "lookback_days": 90,
            "include_live_dns": True,
            "include_subdomains": True,
            "include_d8s": True,
            "include_historical_whois": False,
            "include_ns_glue": True,
            "include_ns2domain": False,
            "include_mx2domain": False,
            "include_email_pivots": False,
            "confidence": 60,
            "marking_definition": "TLP:AMBER",
        },
    }
