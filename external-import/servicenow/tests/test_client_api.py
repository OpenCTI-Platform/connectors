# isort: skipfile
"""Offer tests for client_api"""

from unittest.mock import AsyncMock, Mock
from urllib.parse import urlparse

import pytest
from src.connector.services.client_api import ServiceNowClient


@pytest.fixture()
def mock_client():
    helper = Mock()
    config = Mock()

    config.servicenow.api_leaky_bucket_rate = 10
    config.servicenow.api_leaky_bucket_capacity = 10

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
@pytest.mark.parametrize(
    "config_labels, mock_response, expected_result",
    [
        (
            # Handling "State"
            ["Closed", "NotExisting", "Cancelled"],
            {
                "result": [
                    {"label": "Eradicate", "value": "19"},
                    {"label": "Analysis", "value": "16"},
                    {"label": "Closed", "value": "3"},
                    {"label": "Cancelled", "value": "7"},
                    {"label": "Draft", "value": "10"},
                    {"label": "Contain", "value": "18"},
                    {"label": "Review", "value": "100"},
                    {"label": "Recover", "value": "20"},
                ]
            },
            "3,7",
        ),
        (
            # Handling "Severity"
            ["medium", "low", "NotExisting"],
            {
                "result": [
                    {"label": "1 - High", "value": "1"},
                    {"label": "2 - Medium", "value": "2"},
                    {"label": "3 - Low", "value": "3"},
                ]
            },
            "2,3",
        ),
        (
            # Handling "Priority"
            ["NotExisting", "low"],
            {
                "result": [
                    {"label": "2 - High", "value": "2"},
                    {"label": "3 - Moderate", "value": "3"},
                    {"label": "4 - Low", "value": "4"},
                    {"label": "5 - Planning", "value": "5"},
                    {"label": "1 - Critical", "value": "1"},
                ]
            },
            "4",
        ),
    ],
    ids=[
        "Match and filter multiple labels for state",
        "Match and filter multiple labels for severity",
        "Match and filter multiple labels for priority",
    ],
)
async def test_list_matched(config_labels, mock_response, expected_result):
    # Given a mocked client with a mock request_data
    client = Mock()
    client._request_data = AsyncMock(return_value=mock_response)
    client.helper = Mock()
    client.helper.connector_logger = Mock()
    # When calling list_matched
    result = await ServiceNowClient._list_matched(
        client,
        targeted_labels=config_labels,
        table_name="sys_choice",
        query_parameters="dummy_params",
    )
    # Then the results should be in the values matching the labels
    assert result == expected_result
