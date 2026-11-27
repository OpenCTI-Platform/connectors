import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector import ConnectorState


def test_connector_state_fields_default_to_none():
    assert all(field.default is None for field in ConnectorState.model_fields.values())


def test_connector_state_fields_are_json_serializable():
    state = ConnectorState(
        last_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    json.dumps(state.model_dump(mode="json"))  # must not raise


def _state_with_client(stored_state: dict) -> ConnectorState:
    helper = MagicMock()
    helper.get_state.return_value = stored_state
    state = ConnectorState()
    state.inject_dependencies(helper)
    return state


def test_load_should_read_the_stored_checkpoint():
    state = _state_with_client({"last_modified": "2026-01-12T00:00:00+00:00"})

    state.load(force=True)

    assert state.last_modified == datetime(2026, 1, 12, tzinfo=timezone.utc)


def test_load_should_reset_the_checkpoint_after_a_state_reset_in_opencti():
    # Given: a checkpoint in memory from a previous run
    state = _state_with_client({})
    state.last_modified = datetime(2026, 1, 12, tzinfo=timezone.utc)

    # When: the state was reset from the OpenCTI UI (empty stored state)
    state.load(force=True)

    # Then: the next run starts from scratch
    assert state.last_modified is None


def test_load_should_keep_unsaved_changes_when_not_forced():
    state = _state_with_client({"last_modified": "2026-01-01T00:00:00+00:00"})
    state.load(force=True)
    state.last_modified = datetime(2026, 1, 12, tzinfo=timezone.utc)

    with pytest.warns(UserWarning):
        state.load()  # not forced, the change is not saved yet

    assert state.last_modified == datetime(2026, 1, 12, tzinfo=timezone.utc)
