from unittest.mock import MagicMock

import pytest
import requests
from external_import_connector.client_api import ConnectorClient
from external_import_connector.connector import ConnectorState, ConnectorURLhaus


def _client(get_side_effect=None, get_return=None):
    config = MagicMock()
    config.urlhaus.csv_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    config.urlhaus.import_offline = True
    client = ConnectorClient(MagicMock(), config, ConnectorState())
    client.session = MagicMock()
    if get_side_effect is not None:
        client.session.get.side_effect = get_side_effect
    else:
        client.session.get.return_value = get_return
    return client


def test_get_entities_raises_when_download_fails():
    """A failed download must surface, not end as an empty generator."""
    client = _client(get_side_effect=requests.ConnectionError("unreachable"))

    with pytest.raises(requests.ConnectionError):
        list(client.get_entities())

    client.helper.connector_logger.error.assert_called_once()


def test_get_entities_raises_on_http_error_status():
    response = MagicMock()
    response.raise_for_status.side_effect = requests.HTTPError("503")
    client = _client(get_return=response)

    with pytest.raises(requests.HTTPError):
        list(client.get_entities())


def test_get_entities_yields_rows_when_download_succeeds():
    response = MagicMock()
    response.text = (
        "# comment line\n"
        '"1","2026-01-01 10:00:00","http://bad.example/x","online","",'
        '"malware_download","tag","https://urlhaus.abuse.ch/url/1/","reporter"\n'
    )
    client = _client(get_return=response)

    rows = [row for batch in client.get_entities() for row in batch]

    assert len(rows) == 1
    assert rows[0][2] == "http://bad.example/x"


def test_process_message_marks_work_in_error_and_keeps_state():
    """The work is marked in error and no state is stored when the run fails."""
    connector = ConnectorURLhaus.__new__(ConnectorURLhaus)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = {"last_processed_entry": 42}
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.state = ConnectorState()
    connector.client = _client(get_side_effect=requests.ConnectionError("down"))
    connector.converter_to_stix = MagicMock()

    connector.process_message()

    connector.helper.api.work.to_processed.assert_called_once()
    args, kwargs = connector.helper.api.work.to_processed.call_args
    assert args[0] == "work-1"
    assert kwargs.get("in_error") is True
    assert "successfully" not in args[1]
    connector.helper.set_state.assert_not_called()
