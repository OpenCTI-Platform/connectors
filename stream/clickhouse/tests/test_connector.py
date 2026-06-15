import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from connector.connector import ClickHouseConnector


def _make_connector(live_stream_id: str = "live"):
    helper = MagicMock()
    helper.connect_live_stream_id = live_stream_id
    with patch("connector.connector.ClickHouseClient") as client_cls:
        connector = ClickHouseConnector(config=MagicMock(), helper=helper)
    return connector, helper, client_cls.return_value


def _message(event: str, data: dict) -> SimpleNamespace:
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


def test_create_event_is_inserted():
    connector, _, client = _make_connector()
    client.insert_event.return_value = True

    connector.process_message(
        _message("create", {"id": "indicator--1", "type": "indicator"})
    )

    client.insert_event.assert_called_once()
    assert client.insert_event.call_args.args[0] == "create"


def test_delete_event_is_inserted():
    connector, _, client = _make_connector()
    client.insert_event.return_value = True

    connector.process_message(
        _message("delete", {"id": "indicator--1", "type": "indicator"})
    )

    client.insert_event.assert_called_once()
    assert client.insert_event.call_args.args[0] == "delete"


@pytest.mark.parametrize("live_stream_id", [None, "ChangeMe"])
def test_check_stream_id_raises_when_missing(live_stream_id):
    connector, _, _ = _make_connector(live_stream_id=live_stream_id)

    with pytest.raises(ValueError):
        connector.check_stream_id()


def test_process_message_raises_on_invalid_payload():
    connector, _, _ = _make_connector()

    with pytest.raises(ValueError):
        connector.process_message(SimpleNamespace(event="create", data="not-json"))


def test_run_ensures_table_and_listens():
    connector, helper, client = _make_connector()

    connector.run()

    client.ensure_table.assert_called_once()
    helper.listen_stream.assert_called_once_with(
        message_callback=connector.process_message
    )
