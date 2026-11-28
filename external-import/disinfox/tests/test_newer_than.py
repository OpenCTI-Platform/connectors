import re
from unittest.mock import Mock

from external_import_connector.connector import ConnectorDisinfox

# Format documented by the DISINFOX API, e.g. 2024-10-30T01:35:21.128381Z
NEWER_THAN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def make_connector(state):
    connector = ConnectorDisinfox.__new__(ConnectorDisinfox)
    store = {"state": state}
    connector.helper = Mock()
    connector.helper.get_state.side_effect = lambda: store["state"]
    connector.helper.set_state.side_effect = lambda new: store.update(state=new)
    connector.client = Mock()
    connector.client.get_entities.return_value = [{"type": "identity"}]
    return connector


def sent_newer_than(connector):
    return connector.client.get_entities.call_args.kwargs["params"]["newer_than"]


def test_first_run_and_next_run_send_documented_format():
    connector = make_connector(None)

    connector._collect_intelligence()
    assert sent_newer_than(connector) == "1970-01-01T00:00:00.000000Z"

    stored = connector.helper.get_state()["last_fetch"]
    assert NEWER_THAN.match(stored)

    connector._collect_intelligence()
    assert sent_newer_than(connector) == stored


def test_state_without_last_fetch_uses_utc_epoch():
    connector = make_connector({"last_run": "2026-01-01 00:00:00"})

    connector._collect_intelligence()

    assert sent_newer_than(connector) == "1970-01-01T00:00:00.000000Z"


def test_last_fetch_stored_by_previous_versions_is_normalized():
    connector = make_connector({"last_fetch": "2026-01-02T03:04:05.000006+00:00Z"})

    connector._collect_intelligence()

    assert sent_newer_than(connector) == "2026-01-02T03:04:05.000006Z"
