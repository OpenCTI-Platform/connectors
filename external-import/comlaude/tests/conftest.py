import os
import sys

import pytest
from pycti import OpenCTIApiClient, OpenCTIApiConnector

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("COMLAUDE_USERNAME", "test-user")
    monkeypatch.setenv("COMLAUDE_PASSWORD", "test-password")
    monkeypatch.setenv("COMLAUDE_API_KEY", "test-api-key")
    monkeypatch.setenv("COMLAUDE_GROUP_ID", "test-group-id")


@pytest.fixture(autouse=True)
def mock_health_check(monkeypatch):
    monkeypatch.setattr(OpenCTIApiClient, "health_check", lambda self: True)


@pytest.fixture(autouse=True)
def mock_ping(monkeypatch):
    monkeypatch.setattr(
        OpenCTIApiConnector,
        "ping",
        lambda self, connector_id, initial_state, connector_info: {
            "id": "CHANGEME",
            "connector_user_id": "1",
            "connector_state": "{}",
        },
    )


@pytest.fixture(autouse=True)
def mock_register(monkeypatch):
    monkeypatch.setattr(
        OpenCTIApiConnector,
        "register",
        lambda self, connector: {
            "id": "CHANGEME",
            "connector_user_id": "1",
            "connector_state": "{}",
            "config": {
                "connection": {
                    "host": "rabbitmq",
                    "vhost": "/",
                    "use_ssl": False,
                    "port": 5672,
                    "user": "opencti",
                    "pass": "changeme",
                }
            },
            "jwks": {},
        },
    )
