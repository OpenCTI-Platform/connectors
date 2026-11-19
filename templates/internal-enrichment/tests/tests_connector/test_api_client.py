"""Tests of `TemplateClient`, the example API client.

These tests do not call the real API: `_get` (from `BaseClientApi`) is
replaced with a mock.

TODO:
    - [ ] Replace these tests with tests of your own client's methods.
"""

from unittest.mock import patch

import pytest
from connectors_sdk import ApiNotFoundError
from template_client import IPReputation, TemplateClient


@pytest.fixture
def client() -> TemplateClient:
    """A `TemplateClient` for a fake API."""
    return TemplateClient(base_url="https://api.example.com/v1", api_key="test-key")


def test_get_ip_reputation_should_return_a_validated_model(client):
    """Test that the API response is validated into an `IPReputation`."""
    # Given: the API returns the reputation of the IP
    response = {"ip": "1.2.3.4", "score": 80, "tags": ["scanner"]}

    with patch.object(client, "_get", return_value=response) as get:
        # When: the reputation is fetched
        reputation = client.get_ip_reputation("1.2.3.4")

    # Then: the right endpoint is called, and the response is validated
    get.assert_called_once_with("/ip/1.2.3.4")
    assert reputation == IPReputation(ip="1.2.3.4", score=80, tags=["scanner"])


def test_get_ip_reputation_should_raise_api_errors(client):
    """Test that the client lets API errors go up to the processor."""
    # Given: the API does not know the IP
    with patch.object(client, "_get", side_effect=ApiNotFoundError("Not found")):
        # When: the reputation is fetched
        # Then: the error is raised
        with pytest.raises(ApiNotFoundError):
            client.get_ip_reputation("1.2.3.4")
