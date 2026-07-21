import json
from unittest.mock import MagicMock, patch

import pytest
from connector.connector import TrellixTieConnector
from trellix_tie_client import TrellixTieAPIError


def _make_connector():
    helper = MagicMock()
    helper.connect_live_stream_id = "live"
    with patch("connector.connector.TrellixTieClient") as client_cls:
        connector = TrellixTieConnector(config=MagicMock(), helper=helper)
    connector.client = client_cls.return_value
    connector.trust_level = "KNOWN_MALICIOUS"
    connector.comment = "Set by OpenCTI"
    return connector, helper, connector.client


def _msg(event: str, data: dict) -> MagicMock:
    msg = MagicMock()
    msg.event = event
    msg.data = json.dumps({"data": data})
    return msg


_INDICATOR = {
    "type": "indicator",
    "name": "bad file",
    "pattern": "[file:hashes.'SHA-256' = 'aabbccddeeff']",
    "pattern_type": "stix",
}


def test_create_indicator_sets_reputation():
    connector, _, client = _make_connector()
    connector.process_message(_msg("create", _INDICATOR))

    client.set_file_reputation.assert_called_once()
    args, kwargs = client.set_file_reputation.call_args
    assert args[0] == "KNOWN_MALICIOUS"
    assert kwargs["filename"] == "bad file"


def test_update_indicator_sets_reputation():
    connector, _, client = _make_connector()
    connector.process_message(_msg("update", _INDICATOR))
    client.set_file_reputation.assert_called_once()


def test_non_indicator_skipped():
    connector, _, client = _make_connector()
    connector.process_message(_msg("create", {"type": "malware", "name": "x"}))
    client.set_file_reputation.assert_not_called()


def test_indicator_without_hash_skipped():
    connector, _, client = _make_connector()
    connector.process_message(
        _msg(
            "create",
            {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
        )
    )
    client.set_file_reputation.assert_not_called()


def test_delete_event_ignored():
    connector, _, client = _make_connector()
    connector.process_message(_msg("delete", _INDICATOR))
    client.set_file_reputation.assert_not_called()


def test_reputation_error_is_logged():
    connector, helper, client = _make_connector()
    client.set_file_reputation.side_effect = TrellixTieAPIError("boom")

    connector.process_message(_msg("create", _INDICATOR))  # must not raise
    helper.connector_logger.error.assert_called()


@pytest.mark.parametrize(
    "live_stream_id",
    [None, "ChangeMe", "CHANGEME", "changeme", "  ChangeMe  ", "", "   "],
)
def test_check_stream_id_raises_when_missing(live_stream_id):
    connector, helper, _ = _make_connector()
    helper.connect_live_stream_id = live_stream_id

    with pytest.raises(ValueError):
        connector.check_stream_id()


def test_run_aborts_when_stream_id_missing():
    # A placeholder/blank stream id must fail fast at startup, before listen_stream.
    connector, helper, _ = _make_connector()
    helper.connect_live_stream_id = "ChangeMe"

    with pytest.raises(ValueError):
        connector.run()

    helper.listen_stream.assert_not_called()


def test_run_listens_stream():
    connector, helper, _ = _make_connector()
    connector.run()
    helper.listen_stream.assert_called_once()
