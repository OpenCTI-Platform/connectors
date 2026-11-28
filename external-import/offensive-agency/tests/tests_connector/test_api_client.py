from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk import (
    ApiClientError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)
from offensive_agency_client import OffensiveAgencyClient


@pytest.fixture
def client() -> OffensiveAgencyClient:
    return OffensiveAgencyClient(
        base_url="https://example.com/api/v1", logger=MagicMock()
    )


def test_get_feed_should_keep_tools_indicators_and_relationships(client, raw_feed):
    with patch.object(client, "_get", return_value=raw_feed) as get:
        feed = client.get_feed()

    get.assert_called_once_with("/feeds/stix.json")
    assert [tool.name for tool in feed.tools] == ["Agent Alpha", "Agent Beta"]
    assert len(feed.indicators) == 2
    assert len(feed.relationships) == 3


def test_get_feed_should_turn_null_lists_into_empty_lists(client, raw_feed):
    with patch.object(client, "_get", return_value=raw_feed):
        feed = client.get_feed()

    beta = feed.tools[1]
    assert beta.tool_types == []
    assert beta.external_references == []
    assert feed.indicators[1].external_references == []


def test_get_feed_should_skip_and_log_an_invalid_object(client, raw_feed):
    # Given: an indicator without its pattern
    del raw_feed["objects"][3]["pattern"]

    with patch.object(client, "_get", return_value=raw_feed):
        feed = client.get_feed()

    # Then: it is skipped with a warning, the others are kept
    assert [i.id for i in feed.indicators] == [
        "indicator--00000000-0000-5000-8000-000000000202"
    ]
    client._logger.warning.assert_called_once()


def test_get_feed_should_raise_when_the_response_is_not_a_bundle(client):
    with patch.object(client, "_get", return_value={"error": "maintenance"}):
        with pytest.raises(ProviderApiInvalidResponseError):
            client.get_feed()


@pytest.mark.parametrize(
    "raised, expected",
    [
        pytest.param(requests.Timeout(), ProviderApiTimeoutError, id="timeout"),
        pytest.param(
            requests.ConnectionError(), ProviderApiConnectionError, id="connection"
        ),
        pytest.param(
            ApiRateLimitError("Too many requests", status_code=429),
            ProviderApiRateLimitError,
            id="rate_limit",
        ),
        pytest.param(
            ApiServerError("Server error", status_code=503),
            ProviderApiServerError,
            id="server_error",
        ),
        pytest.param(
            ApiNotFoundError("Not found", status_code=404),
            ProviderApiNotFoundError,
            id="not_found",
        ),
        pytest.param(
            ApiClientError("Malformed JSON", status_code=200),
            ProviderApiUnknownError,
            id="other_client_error",
        ),
    ],
)
def test_get_feed_should_raise_sdk_provider_errors(client, raised, expected):
    with patch.object(client, "_get", side_effect=raised):
        with pytest.raises(expected) as err:
            client.get_feed()

    assert err.value.__cause__ is raised
    # Logged once at the top level by the SDK, not here
    client._logger.exception.assert_not_called()


def test_client_should_send_a_user_agent(client):
    assert client.session_headers["User-Agent"] == "OpenCTI-connector-offensive-agency"
