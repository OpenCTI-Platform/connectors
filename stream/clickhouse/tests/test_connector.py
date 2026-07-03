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


def test_event_write_is_logged_at_debug_not_info():
    # Per-event writes are logged at DEBUG: live streams are high-volume, so an
    # INFO line per event would flood logs. INFO is reserved for startup/summary.
    connector, helper, client = _make_connector()
    client.insert_event.return_value = True

    connector.process_message(
        _message("create", {"id": "indicator--1", "type": "indicator"})
    )

    helper.connector_logger.debug.assert_called_once()
    helper.connector_logger.info.assert_not_called()


def test_failed_event_write_is_logged_at_error():
    # A failed insert must not pass silently: the dropped event is logged at
    # ERROR with the entity id so the loss is traceable.
    connector, helper, client = _make_connector()
    client.insert_event.return_value = False

    connector.process_message(
        _message("create", {"id": "indicator--1", "type": "indicator"})
    )

    helper.connector_logger.error.assert_called_once()
    assert (
        helper.connector_logger.error.call_args.kwargs["meta"]["id"] == "indicator--1"
    )
    helper.connector_logger.debug.assert_not_called()


@pytest.mark.parametrize(
    "live_stream_id",
    [None, "ChangeMe", "CHANGEME", "changeme", "  ChangeMe  ", "", "   "],
)
def test_check_stream_id_raises_when_missing(live_stream_id):
    connector, _, _ = _make_connector(live_stream_id=live_stream_id)

    with pytest.raises(ValueError):
        connector.check_stream_id()


@pytest.mark.parametrize("live_stream_id", ["live", "a-real-stream-uuid"])
def test_check_stream_id_accepts_real_id(live_stream_id):
    connector, _, _ = _make_connector(live_stream_id=live_stream_id)

    connector.check_stream_id()


def test_process_message_raises_on_invalid_payload():
    connector, _, _ = _make_connector()

    with pytest.raises(ValueError):
        connector.process_message(SimpleNamespace(event="create", data="not-json"))


def test_run_ensures_table_and_listens():
    connector, helper, client = _make_connector()
    client.ensure_table.return_value = True

    connector.run()

    client.ensure_table.assert_called_once()
    helper.listen_stream.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_run_aborts_when_schema_cannot_be_ensured():
    connector, helper, client = _make_connector()
    client.ensure_table.return_value = False

    with pytest.raises(RuntimeError):
        connector.run()

    helper.listen_stream.assert_not_called()


def test_run_aborts_when_stream_id_missing():
    # A placeholder/blank stream id must fail fast at startup, before the schema
    # is created or the stream is listened to.
    connector, helper, client = _make_connector(live_stream_id="ChangeMe")

    with pytest.raises(ValueError):
        connector.run()

    client.ensure_table.assert_not_called()
    helper.listen_stream.assert_not_called()


def test_event_timestamp_is_derived_from_stream_id():
    # OpenCTI event ids are Redis stream ids: "<milliseconds>-<sequence>".
    msg = SimpleNamespace(id="1700000000123-0")
    assert ClickHouseConnector._event_timestamp(msg) == 1700000000


def test_event_timestamp_falls_back_when_id_missing():
    msg = SimpleNamespace(event="create", data="{}")
    assert ClickHouseConnector._event_timestamp(msg) > 0


def test_event_timestamp_falls_back_when_id_unparseable():
    # A non-numeric event id must not raise; it falls back to the receipt time.
    msg = SimpleNamespace(id="not-a-redis-id")
    assert ClickHouseConnector._event_timestamp(msg) > 0


def test_process_message_passes_event_date_to_client():
    connector, _, client = _make_connector()
    client.insert_event.return_value = True

    msg = SimpleNamespace(
        id="1700000000123-0",
        event="create",
        data=json.dumps({"data": {"id": "indicator--1", "type": "indicator"}}),
    )
    connector.process_message(msg)

    assert client.insert_event.call_args.args[0] == "create"
    assert client.insert_event.call_args.args[2] == 1700000000
