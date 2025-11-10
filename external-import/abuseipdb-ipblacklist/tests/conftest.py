import os
import sys

import pytest
from pycti import OpenCTIApiClient, OpenCTIApiConnector
from src.external_import_connector.config_variables import ConfigConnector

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_SCORE", "90")
    monkeypatch.setenv("ABUSEIPDB_CREATE_INDICATOR", "true")


@pytest.fixture(autouse=True)
def mock_config(monkeypatch):
    monkeypatch.setattr(
        ConfigConnector,
        "_load_config",
        lambda self: {
            "opencti": {
                "url": "http://localhost:8080",
                "token": "changeme",
                "ssl_verify": False,
            },
            "connector": {
                "id": "CHANGEME",
                "name": "AbuseIPDB Connector",
                "type": "EXTERNAL_IMPORT",
            },
        },
    )


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
        },
    )
