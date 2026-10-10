import json
from datetime import datetime, timezone

from connector import ConnectorState


def test_fields_default_to_none():
    state = ConnectorState()
    assert state.last_run is None
    assert state.deployed_rules is None
    assert state.pending_removals is None


def test_state_round_trips_through_json():
    state = ConnectorState(
        last_run=datetime(2026, 10, 3, tzinfo=timezone.utc),
        deployed_rules={"rule-1": "indicator--5b3d4a2c-0000-4000-8000-000000000001"},
        pending_removals={"indicator--5b3d4a2c-0000-4000-8000-000000000002": "r2"},
    )
    dumped = json.loads(json.dumps(state.model_dump(mode="json")))
    restored = ConnectorState(**dumped)
    assert restored.deployed_rules == state.deployed_rules
    assert restored.pending_removals == state.pending_removals
    assert restored.last_run == state.last_run
