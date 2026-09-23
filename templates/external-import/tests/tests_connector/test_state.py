"""Tests for `ConnectorState` -- the connector's persisted checkpoints.

These tests only check the generic contract every state class must respect,
regardless of which checkpoint fields it defines: it must be safe to build
with no data (a brand new connector has never run before), and every field
must be JSON-serializable, since that is how OpenCTI persists it between two
runs. Parsing it back is pydantic/`connectors-sdk`'s own responsibility, and
is not re-tested here.

Note:
    `last_report_update`/`vulnerabilities_current_page` are the two EXAMPLE
    checkpoint fields described in `connector/state.py` -- they belong to
    the fictional `ReportsProcessor`/`VulnerabilitiesProcessor` and are only
    used here to demonstrate the pattern. Adapt these tests to your own
    checkpoint fields once you replace the example processors.
"""

import json
from datetime import datetime, timezone

from connector import ConnectorState


def test_connector_state_fields_default_to_none():
    """
    Every field in `ConnectorState` must default to `None`, so they're all
    optional *and* removable from the state.
    """
    assert all(field.default is None for field in ConnectorState.model_fields.values())


def test_connector_state_fields_are_set_to_none_on_init():
    """
    A connector that never ran before must start from a clean state: every
    field must be set to `None` (no `field_validator`/`model_validator` should override defaults).
    """
    state = ConnectorState()

    assert state.last_run is None
    assert state.last_report_update is None
    assert state.vulnerabilities_current_page is None


def test_connector_state_fields_are_json_serializable():
    """
    OpenCTI persists the connector state as JSON between two runs. Every
    field must therefore serialize to a JSON-safe value (e.g. a `datetime`
    becomes an ISO 8601 string).
    """
    state = ConnectorState(
        last_run=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_report_update=datetime(2024, 1, 2, tzinfo=timezone.utc),
        vulnerabilities_current_page=3,
    )

    state_json = state.model_dump(mode="json")

    json.dumps(state_json)  # must not raise: every value is JSON-safe
