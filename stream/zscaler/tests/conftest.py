import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from pycti import OpenCTIConnectorHelper
from stream_connector import connector as zscaler


@pytest.fixture(autouse=True)
def mock_obfuscate(monkeypatch):
    """Mock obfuscate_api_key to return a dummy string."""
    monkeypatch.setattr(
        "stream_connector.utils.obfuscate_api_key",
        lambda api_key, timestamp: "dummy-obfuscated",
    )


@pytest.fixture
def connector(helper_mock, mock_config, mock_session, mock_opencti_client):
    """Provide a ZscalerConnector instance with mocked config, session and OpenCTI client"""

    zscaler_connector = zscaler.ZscalerConnector(
        config_path=None,
        helper=helper_mock,
        opencti_url=mock_config.opencti.url,
        opencti_token=mock_config.opencti.token,
        ssl_verify=mock_config.ssl_verify,
        zscaler_username=mock_config.zscaler.username,
        zscaler_password=mock_config.zscaler.password,
        zscaler_api_key=mock_config.zscaler.api_key,
        zscaler_blacklist_name=mock_config.zscaler.blacklist_name,
    )
    zscaler_connector.session = mock_session
    return zscaler_connector


@pytest.fixture
def mock_config():
    """Simulate configuration values for ZscalerConnector"""
    mock = Mock()
    mock.opencti.url = "https://opencti.example.com"
    mock.opencti.token = "dummy-token"
    mock.ssl_verify = False
    mock.zscaler.username = "user"
    mock.zscaler.password = "pass"
    mock.zscaler.api_key = "api-key"
    mock.zscaler.blacklist_name = "blacklist"
    return mock


@pytest.fixture
def mock_opencti_client(monkeypatch):
    mock_client = Mock()
    mock_client.health_check.return_value = True

    monkeypatch.setattr(
        zscaler, "OpenCTIApiClient", lambda *args, **kwargs: mock_client
    )

    return mock_client


@pytest.fixture
def helper_mock():
    """Mock OpenCTIConnectorHelper with logger and listen_stream"""
    helper = Mock(spec=OpenCTIConnectorHelper)
    helper.connector_logger = Mock()
    helper.listen_stream = Mock()
    return helper


@pytest.fixture
def mock_session(monkeypatch):
    """Patch requests.Session to avoid real HTTP calls"""

    mock_sess = Mock()
    monkeypatch.setattr(zscaler.requests, "Session", lambda: mock_sess)
    return mock_sess
