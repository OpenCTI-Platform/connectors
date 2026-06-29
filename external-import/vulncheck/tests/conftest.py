import os
import sys
from unittest.mock import patch

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def correct_config():
    with patch(
        "os.environ",
        {
            "OPENCTI_URL": "http://localhost:8080",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "connector_id",
            "CONNECTOR_NAME": "VulnCheck Connector",
            "CONNECTOR_TYPE": "EXTERNAL_IMPORT",
            "CONNECTOR_LOG_LEVEL": "error",
            "CONNECTOR_SCOPE": "vulnerability,malware,threat-actor",
            "CONNECTOR_DURATION_PERIOD": "PT1H",
            "VULNCHECK_API_KEY": "test_api_key",
            "VULNCHECK_API_BASE_URL": "https://api.vulncheck.com/v3",
            "VULNCHECK_DATA_SOURCES": "vulncheck-kev,nist-nvd2",
        },
    ):
        yield


@pytest.fixture
def deprecated_config():
    with patch(
        "os.environ",
        {
            "OPENCTI_URL": "http://localhost:8080",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "connector_id",
            "CONNECTOR_NAME": "VulnCheck Connector",
            "CONNECTOR_TYPE": "EXTERNAL_IMPORT",
            "CONNECTOR_LOG_LEVEL": "error",
            "CONNECTOR_SCOPE": "vulnerability,malware,threat-actor",
            "CONNECTOR_DURATION_PERIOD": "PT1H",
            "CONNECTOR_VULNCHECK_API_KEY": "test_api_key",
            "CONNECTOR_VULNCHECK_API_BASE_URL": "https://api.vulncheck.com/v3",
            "CONNECTOR_VULNCHECK_DATA_SOURCES": "vulncheck-kev,nist-nvd2",
        },
    ):
        yield


@pytest.fixture(autouse=True)
def health_check_mock():
    with patch("pycti.OpenCTIApiClient.health_check", return_value=True):
        yield


@pytest.fixture(autouse=True)
def connector_register_mock():
    with patch(
        "pycti.OpenCTIApiConnector.register",
        return_value={
            "id": "connector_id",
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
    ):
        yield


@pytest.fixture(autouse=True)
def connector_ping_mock():
    with patch(
        "pycti.OpenCTIApiConnector.ping",
        return_value={"connector_state": '{"last_run": "2024-01-01T00:00:00Z"}'},
    ):
        yield


@pytest.fixture(autouse=True)
def work_initiate_mock():
    with patch(
        "pycti.OpenCTIApiWork.initiate_work", return_value={"id": "work_id_123"}
    ):
        yield


@pytest.fixture(autouse=True)
def to_processed_mock():
    with patch("pycti.OpenCTIApiWork.to_processed", return_value=True):
        yield
