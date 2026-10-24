"""Tests for `TemplateClient`, the EXAMPLE API client.

They show how to test a client without calling the real API: the requests made by
`BaseClientApi` (`_get`, `_paginate_offset`) are replaced with fakes.

TODO:
    - [ ] Replace these tests with tests of your own client's methods
"""

from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk import ApiClientError
from template_client.api_client import TemplateClient


@pytest.fixture
def client() -> TemplateClient:
    """A `TemplateClient` with a mock logger, to check what it logs."""
    return TemplateClient(api_key="test-api-key", logger=MagicMock())


def test_get_reports_should_log_and_raise_api_errors(client):
    """Test that an API error is logged, then raised to the processor."""
    # Given: the API returns an error
    api_error = ApiClientError("Server error", status_code=500)

    with patch.object(client, "_get", side_effect=api_error):
        # When: the reports are fetched
        # Then: the error is raised
        with pytest.raises(ApiClientError):
            client.get_reports()

    # Then: the error is logged, with its traceback
    client._logger.exception.assert_called_once()


def test_iter_cves_should_log_and_raise_api_errors(client):
    """Test that an API error is logged, then raised to the processor."""
    # Given: the API returns an error
    api_error = ApiClientError("Server error", status_code=500)

    with patch.object(client, "_paginate_offset", side_effect=api_error):
        # When: the CVEs are fetched
        # Then: the error is raised
        with pytest.raises(ApiClientError):
            list(client.iter_cves())

    # Then: the error is logged, with its traceback
    client._logger.exception.assert_called_once()
