from unittest.mock import MagicMock

import pytest
import requests
from montysecurity_c2_tracker_client import (
    MontysecurityC2TrackerClient,
    MontysecurityC2TrackerSourceError,
)


def _response(status_code: int, text: str = "") -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = text.encode()
    response.url = "https://example.test/data"
    return response


@pytest.fixture
def client(mock_connector_settings):
    helper = MagicMock()
    c2_client = MontysecurityC2TrackerClient(
        helper, mock_connector_settings.montysecurity_c2_tracker
    )
    c2_client.session = MagicMock()
    return c2_client


def test_get_malware_list_returns_the_listed_files(client):
    client.session.get.return_value = _response(
        200, '<a>"Cobalt Strike C2 IPs.txt"</a> <a>"Sliver C2 IPs.txt"</a>'
    )

    assert sorted(client.get_malware_list()) == [
        "Cobalt Strike C2 IPs.txt",
        "Sliver C2 IPs.txt",
    ]


def test_get_malware_list_raises_when_the_source_answers_404(client):
    """The upstream data was removed (issue #8169): the run must fail, not succeed empty."""
    client.session.get.return_value = _response(404, "Not Found")

    with pytest.raises(MontysecurityC2TrackerSourceError, match="cannot be reached"):
        client.get_malware_list()


def test_get_malware_list_raises_when_the_source_cannot_be_reached(client):
    client.session.get.side_effect = requests.ConnectionError("connection refused")

    with pytest.raises(MontysecurityC2TrackerSourceError, match="cannot be reached"):
        client.get_malware_list()


def test_get_malware_list_raises_when_the_source_lists_no_file(client):
    client.session.get.return_value = _response(200, "<html>no data here</html>")

    with pytest.raises(MontysecurityC2TrackerSourceError, match="no malware file"):
        client.get_malware_list()


def test_process_message_does_not_store_last_run_when_the_source_fails(
    mock_connector,
):
    mock_connector.client.get_malware_list.side_effect = (
        MontysecurityC2TrackerSourceError("Malware list source cannot be reached")
    )
    mock_connector.helper.get_state = MagicMock(return_value=None)
    mock_connector.helper.set_state = MagicMock()
    mock_connector.helper.connector_logger = MagicMock()

    mock_connector.process_message()

    mock_connector.helper.set_state.assert_not_called()
    mock_connector.helper.connector_logger.error.assert_called_once()
