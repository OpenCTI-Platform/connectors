import os
import sys
from unittest.mock import MagicMock

import pytest
from splunk_test_support import DEPLOYMENT_VARIABLES, SPLUNK_URL

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def splunk_environment(monkeypatch):
    """Minimal environment of the Splunk connector."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "connector--splunk-test")
    monkeypatch.setenv("CONNECTOR_LIVE_STREAM_ID", "live")
    monkeypatch.setenv("SPLUNK_URL", SPLUNK_URL)
    monkeypatch.setenv("SPLUNK_TOKEN", "splunk-token")
    monkeypatch.setenv("SPLUNK_OWNER", "nobody")
    monkeypatch.setenv("SPLUNK_APP", "search")
    monkeypatch.setenv("SPLUNK_KV_STORE_NAME", "opencti")
    for name in DEPLOYMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


@pytest.fixture
def helper():
    """Connector helper of the stream processing tests."""
    mocked = MagicMock()
    mocked.get_stream_collection.return_value = {"name": "Splunk stream"}
    return mocked
