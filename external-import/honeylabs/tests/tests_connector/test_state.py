import json
from datetime import datetime, timezone

from connector import ConnectorState
from connector.data_processors.indicators_processor import STATE_FIELDS


def test_every_field_defaults_to_none():
    assert all(f.default is None for f in ConnectorState.model_fields.values())
    assert ConnectorState().last_run is None


def test_every_collection_has_a_checkpoint_field():
    fields = set(ConnectorState.model_fields)
    assert set(STATE_FIELDS.values()) <= fields


def test_state_is_json_serializable():
    state = ConnectorState(
        attackers_added_after=datetime(2026, 9, 24, tzinfo=timezone.utc)
    )
    json.dumps(state.model_dump(mode="json"))
