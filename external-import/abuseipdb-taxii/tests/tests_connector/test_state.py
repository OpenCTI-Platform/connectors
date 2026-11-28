import json
from datetime import datetime, timezone

from connector import ConnectorState


def test_connector_state_fields_default_to_none():
    assert all(field.default is None for field in ConnectorState.model_fields.values())

    state = ConnectorState()

    assert state.last_run is None
    assert state.added_after is None
    assert state.next_cursor is None
    assert state.collection_id is None


def test_populated_state_is_json_serializable():
    state = ConnectorState(
        last_run=datetime(2026, 8, 21, tzinfo=timezone.utc),
        added_after="2026-08-21T15:00:00.123456Z",
        next_cursor="opaque-cursor",
        collection_id="feed-id",
    )

    state_json = state.to_json()
    json.dumps(state_json)

    assert state_json["added_after"] == "2026-08-21T15:00:00.123456Z"
    assert state_json["next_cursor"] == "opaque-cursor"
    assert state_json["collection_id"] == "feed-id"
