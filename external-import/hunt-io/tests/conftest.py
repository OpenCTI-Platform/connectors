import gzip
import json
import os
import sys
from unittest.mock import patch

import pytest

from .factories import C2FeedFactory

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def correct_config():
    with patch(
        "os.environ",
        {
            "OPENCTI_URL": "http://url",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "connector_id",
            "CONNECTOR_NAME": "connector_name",
            "CONNECTOR_TYPE": "EXTERNAL_IMPORT",
            "CONNECTOR_LOG_LEVEL": "error",
            "CONNECTOR_SCOPE": "scope",
            "CONNECTOR_DURATION_PERIOD": "PT5M",
            "HUNT_IO_API_BASE_URL": "http://api",
            "HUNT_IO_API_KEY": "api_key_value",
        },
    ):
        yield


@pytest.fixture
def deprecated_config():
    with patch(
        "os.environ",
        {
            "OPENCTI_URL": "http://url",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "connector_id",
            "CONNECTOR_NAME": "connector_name",
            "CONNECTOR_TYPE": "EXTERNAL_IMPORT",
            "CONNECTOR_LOG_LEVEL": "error",
            "CONNECTOR_SCOPE": "scope",
            "CONNECTOR_DURATION_PERIOD": "PT5M",
            "CONNECTOR_HUNT_UI_API_BASE_URL": "http://aaa-api",
            "HUNT_IO_API_KEY": "aaa_api_key_value",
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


@pytest.fixture
def api_response_mock():
    with patch("requests.Session.get") as mock_get:
        c2_feed_batch = C2FeedFactory.create_batch(3)
        json_data = "\n".join([json.dumps(item.to_dict()) for item in c2_feed_batch])
        encoded = json_data.encode("utf-8")
        gzip_buffer = gzip.compress(encoded)
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.content = gzip_buffer
        yield c2_feed_batch


@pytest.fixture
def empty_api_response_mock():
    with patch("requests.Session.get") as mock_get:
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.content = gzip.compress("".encode("utf-8"))
        yield
