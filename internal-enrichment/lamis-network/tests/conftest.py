# -*- coding: utf-8 -*-
"""Pytest configuration for Lamis Network connector tests."""

import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture(autouse=True)
def default_connector_env(monkeypatch):
    """Set default environment variables required by ConnectorSettings."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "4f8a846c-cbe9-4560-a292-ee1d82824707")
    monkeypatch.setenv("CONNECTOR_NAME", "Lamis Network IP Intelligence")
    monkeypatch.setenv("CONNECTOR_SCOPE", "IPv4-Addr,IPv6-Addr")
    monkeypatch.setenv("LAMIS_NETWORK_API_KEY", "test-api-key")
