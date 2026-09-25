from unittest.mock import MagicMock, patch

import pytest
from connector.connector import HatchingTriageSandboxConnector
from triage.client import ServerError


@pytest.fixture
def connector(mock_opencti_connector_helper):
    config = MagicMock()
    config.opencti.url = "http://localhost:8080"
    config.hatching_triage_sandbox.base_url = "https://tria.ge/api"
    config.hatching_triage_sandbox.token.get_secret_value.return_value = "fake-token"
    config.hatching_triage_sandbox.use_existing_analysis = True
    config.hatching_triage_sandbox.family_color = "#0059f7"
    config.hatching_triage_sandbox.botnet_color = "#f79e00"
    config.hatching_triage_sandbox.campaign_color = "#7a01e5"
    config.hatching_triage_sandbox.tag_color = "#54483b"
    config.hatching_triage_sandbox.max_tlp = "TLP:AMBER"

    helper = MagicMock()
    helper.api.identity.create.return_value = {"standard_id": "identity--fake"}

    with patch("connector.connector.Client"):
        instance = HatchingTriageSandboxConnector(config, helper)

    return instance


class TestSearchForAnalysis:
    def test_returns_sample_id_when_reported(self, connector):
        """Should return sample_id when an existing reported analysis is found."""
        connector.triage_client.search.return_value = iter(
            [{"id": "sample-123", "status": "reported"}]
        )

        result = connector._search_for_analysis("url:https://example.com")

        assert result == "sample-123"
        connector.helper.connector_logger.info.assert_called()

    def test_returns_none_when_no_results(self, connector):
        """Should return None when no existing analysis is found."""
        connector.triage_client.search.return_value = iter([])

        result = connector._search_for_analysis("url:https://example.com")

        assert result is None

    def test_returns_none_on_server_error(self, connector):
        """Should return None and log a warning when a ServerError occurs (e.g. 504 timeout)."""
        import json

        mock_response = MagicMock()
        mock_response.status_code = 504
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)

        http_error = MagicMock()
        http_error.response = mock_response

        connector.triage_client.search.return_value = _raise_server_error(http_error)

        result = connector._search_for_analysis("url:https://example.com")

        assert result is None
        connector.helper.connector_logger.warning.assert_called_once()

    def test_returns_none_when_use_existing_analysis_disabled(self, connector):
        """Should return None without searching when use_existing_analysis is False."""
        connector.use_existing_analysis = False

        result = connector._search_for_analysis("url:https://example.com")

        assert result is None
        connector.triage_client.search.assert_not_called()


def _raise_server_error(http_error):
    """Generator that raises a ServerError when iterated."""
    raise ServerError(http_error)
    yield  # noqa: unreachable - makes this a generator
