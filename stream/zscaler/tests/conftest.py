import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from pycti import OpenCTIConnectorHelper
from stream_connector.client import ZscalerClient
from stream_connector.connector import ZscalerConnector


@pytest.fixture
def logger():
    return Mock()


@pytest.fixture
def client(logger):
    """A ZscalerClient whose HTTP session is mocked."""
    zscaler_client = ZscalerClient(
        logger=logger,
        client_id="client-id",
        client_secret="client-secret",
        vanity_domain="acme",
    )
    zscaler_client.session = Mock()
    return zscaler_client


@pytest.fixture
def helper_mock():
    """Mock OpenCTIConnectorHelper with logger and listen_stream"""
    helper = Mock(spec=OpenCTIConnectorHelper)
    helper.connector_logger = Mock()
    helper.listen_stream = Mock()
    return helper


@pytest.fixture
def connector(helper_mock):
    """A ZscalerConnector whose Zscaler client is mocked."""
    return ZscalerConnector(
        helper=helper_mock,
        client=Mock(spec=ZscalerClient),
        zscaler_blacklist_name="CUSTOM_01",
    )
