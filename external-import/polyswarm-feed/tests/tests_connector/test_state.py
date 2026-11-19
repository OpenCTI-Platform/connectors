import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from connector import ConnectorState
from connector.state import CollectionCursor


def test_state_fields_default_to_none():
    assert all(field.default is None for field in ConnectorState.model_fields.values())
    state = ConnectorState()
    assert state.last_run is None
    assert state.collections is None
    assert state.hunting is None


def test_get_cursor_of_unknown_collection_is_empty():
    cursor = ConnectorState().get_cursor("trustgroup")
    assert cursor == CollectionCursor()
    assert cursor.added_after is None and cursor.next_token is None


def test_set_cursor_keeps_other_collections_and_get_returns_a_copy():
    state = ConnectorState()
    state.set_cursor("trustgroup", CollectionCursor(added_after="2026-11-10T00:00:00Z"))
    state.set_cursor("ransomware", CollectionCursor(next_token="token"))

    cursor = state.get_cursor("trustgroup")
    cursor.added_after = "changed"

    assert state.get_cursor("trustgroup").added_after == "2026-11-10T00:00:00Z"
    assert state.get_cursor("ransomware").next_token == "token"


def test_state_is_json_serializable_and_round_trips_through_opencti():
    state = ConnectorState(
        last_run=datetime(2026, 11, 10, tzinfo=timezone.utc),
        hunting={"since": "x", "seen_ids": ["a"]},
    )
    state.set_cursor(
        "trustgroup",
        CollectionCursor(added_after="2026-11-10T14:53:00.403510Z", next_token="t"),
    )
    stored = state.to_json()
    json.dumps(stored)
    assert stored["collections"] == {
        "trustgroup": {"added_after": "2026-11-10T14:53:00.403510Z", "next_token": "t"}
    }

    helper = MagicMock()
    helper.get_state.return_value = json.loads(json.dumps(stored))
    loaded = ConnectorState()
    loaded.inject_dependencies(helper)
    loaded.load(force=True)

    assert loaded.get_cursor("trustgroup").next_token == "t"
    assert loaded.hunting == {"since": "x", "seen_ids": ["a"]}
    assert loaded.last_run == datetime(2026, 11, 10, tzinfo=timezone.utc)


def test_set_cursor_stores_a_copy():
    state = ConnectorState()
    cursor = CollectionCursor(added_after="T1", next_token="n1")
    state.set_cursor("trustgroup", cursor)
    cursor.next_token = None
    assert state.get_cursor("trustgroup").next_token == "n1"


def test_unknown_stored_keys_are_kept():
    helper = MagicMock()
    helper.get_state.return_value = {"legacy": 1}
    state = ConnectorState()
    state.inject_dependencies(helper)
    state.load(force=True)
    assert state.to_json()["legacy"] == 1
