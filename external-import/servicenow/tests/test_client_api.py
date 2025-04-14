# isort: skipfile
"""Offer tests for client_api"""

from unittest.mock import AsyncMock, Mock
from urllib.parse import urlparse

import pytest
from connector.services.client_api import ServiceNowClient


@pytest.fixture()
def mock_client():
    helper = Mock()
    config = Mock()
    return ServiceNowClient(helper=helper, config=config)


def test_build_url(mock_client):
    # Given a ServiceNowClient instance
    client = mock_client
    client.instance_name = "test_instance_name"
    client.api_version = "test_api_version"
    # When calling build_url
    built_url = client._build_url(
        table_name="test_table_name", query_parameters="test_key=test_value"
    )
    # Then the correct url is built
    parsed = urlparse(built_url)
    assert (
        (parsed.netloc == "test_instance_name.service-now.com")
        & ("test_api_version" in parsed.path)
        & ("test_table_name" in parsed.path)
        & (parsed.query == "test_key=test_value")
    )


@pytest.mark.asyncio
async def test_list_matched(mock_client):
    # Given a mocked client with a mock request_data
    # When calling list_matched
    # Then the results should be in the values mmatching the labels
    # and requests_data is called once.
    pass
