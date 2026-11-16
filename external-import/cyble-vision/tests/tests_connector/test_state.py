"""Tests for `ConnectorState`, the checkpoints persisted between runs."""

import json
from datetime import datetime, timezone

from connector import ConnectorState


def test_connector_state_fields_default_to_none():
    """Every field must be optional so a brand new connector starts clean."""
    assert all(field.default is None for field in ConnectorState.model_fields.values())


def test_connector_state_fields_are_set_to_none_on_init():
    state = ConnectorState()

    assert state.last_run is None
    assert state.last_alert_created_at is None
    assert state.last_advisory_publish_date is None
    assert state.last_newsfeed_post_date is None
    assert state.last_newsflash_published_date is None


def test_connector_state_fields_are_json_serializable():
    state = ConnectorState(
        last_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_alert_created_at={"ssl_expiry": "2026-01-02T00:00:00+00:00"},
        last_advisory_publish_date="2026-01-03",
        last_newsfeed_post_date="2026-01-04",
        last_newsflash_published_date="2026-01-05",
    )

    json.dumps(state.model_dump(mode="json"))
