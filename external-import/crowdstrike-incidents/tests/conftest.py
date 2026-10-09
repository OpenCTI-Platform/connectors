"""Pytest configuration and shared fixtures for CrowdStrike Incidents tests."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

# Add src/ to path so we can import the connector package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

RESOURCES_DIR = Path(__file__).resolve().parent / "resources"


def load_resource(name: str) -> Any:
    """Load a JSON test resource by file name."""
    with open(RESOURCES_DIR / name, encoding="utf-8") as file:
        return json.load(file)


@pytest.fixture
def mock_env(monkeypatch) -> None:
    """Set the minimal environment required to build the connector settings."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "00000000-0000-4000-8000-000000000000")
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_CLIENT_ID", "synthetic-client-id")
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_CLIENT_SECRET", "synthetic-secret")


@pytest.fixture
def ngsiem_alert_data() -> dict[str, Any]:
    """A complete, anonymised NG-SIEM alert as returned by /alerts/entities/alerts/v2."""
    return load_resource("ngsiem_alert.json")
