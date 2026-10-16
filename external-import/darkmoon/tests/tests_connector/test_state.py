"""Tests for `ConnectorState` -- the connector's persisted checkpoints."""

import json
from datetime import datetime, timezone

from connector import ConnectorState


def test_connector_state_fields_default_to_none():
    """Every field in `ConnectorState` must default to `None`."""
    assert all(field.default is None for field in ConnectorState.model_fields.values())


def test_connector_state_fields_are_set_to_none_on_init():
    """A connector that never ran before must start from a clean state."""
    state = ConnectorState()

    assert state.last_run is None
    assert state.last_campaign_date is None


def test_connector_state_fields_are_json_serializable():
    """OpenCTI persists the connector state as JSON between two runs."""
    state = ConnectorState(
        last_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_campaign_date=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    state_json = state.model_dump(mode="json")

    json.dumps(state_json)  # must not raise: every value is JSON-safe
