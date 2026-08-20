import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from connector.connector import VectraAIConnector


def _make_connector(live_stream_id: str = "live"):
    helper = MagicMock()
    helper.connect_live_stream_id = live_stream_id
    with patch("connector.connector.VectraClient") as client_cls:
        connector = VectraAIConnector(config=MagicMock(), helper=helper)
    return connector, helper, client_cls.return_value


def _message(event: str, data: dict) -> SimpleNamespace:
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


def test_create_indicator_is_pushed_to_client():
    connector, _, client = _make_connector()
    client.add_indicator.return_value = True

    connector.process_message(
        _message(
            "create",
            {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
            },
        )
    )

    client.add_indicator.assert_called_once()


def test_update_indicator_is_pushed_to_client():
    connector, _, client = _make_connector()
    client.add_indicator.return_value = True

    connector.process_message(
        _message(
            "update",
            {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'evil.example.com']",
            },
        )
    )

    client.add_indicator.assert_called_once()


def test_delete_indicator_is_not_pushed_to_client():
    connector, helper, client = _make_connector()

    connector.process_message(
        _message(
            "delete",
            {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
            },
        )
    )

    client.add_indicator.assert_not_called()
    helper.connector_logger.debug.assert_called_once()


def test_non_indicator_is_ignored():
    connector, _, client = _make_connector()

    connector.process_message(
        _message("create", {"type": "malware", "pattern_type": "stix"})
    )

    client.add_indicator.assert_not_called()


def test_non_stix_pattern_is_ignored():
    connector, _, client = _make_connector()

    connector.process_message(
        _message(
            "create",
            {"type": "indicator", "pattern_type": "pcre", "pattern": "/evil/"},
        )
    )

    client.add_indicator.assert_not_called()


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

    bad_message = SimpleNamespace(event="create", data="not-json")
    with pytest.raises(ValueError):
        connector.process_message(bad_message)


def test_run_listens_to_stream():
    connector, helper, _ = _make_connector()

    connector.run()

    helper.listen_stream.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_run_aborts_when_stream_id_missing():
    # A placeholder/blank stream id must fail fast at startup, before listen_stream.
    connector, helper, _ = _make_connector(live_stream_id="ChangeMe")

    with pytest.raises(ValueError):
        connector.run()

    helper.listen_stream.assert_not_called()
