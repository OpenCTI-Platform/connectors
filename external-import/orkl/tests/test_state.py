"""Tests for the ORKL connector state."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from orkl.state import OrklState


def _state_with_stored(stored: dict) -> OrklState:
    state = OrklState(
        last_library_version=588,
        last_full_sync=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )
    state._client = MagicMock()
    state._client.load_state.return_value = stored
    return state


class TestLoadResetsFields:
    def test_reset_from_platform_clears_in_memory_cursor(self):
        # A state reset in the OpenCTI UI stores `{}`: the cursor must not survive.
        state = _state_with_stored({})
        state.load(force=True)
        assert state.last_library_version is None
        assert state.last_full_sync is None

    def test_stored_values_are_loaded(self):
        state = _state_with_stored(
            {"last_library_version": 600, "last_full_sync": "2026-10-20T00:00:00Z"}
        )
        state.load(force=True)
        assert state.last_library_version == 600
        # Pydantic validates on assignment: the stored ISO string comes back as
        # an aware datetime.
        assert state.last_full_sync == datetime(2026, 10, 20, tzinfo=timezone.utc)

    def test_non_forced_load_with_unsaved_changes_keeps_values(self):
        # The base class refuses to load over unsaved changes; our reset must
        # not run in that case either.
        state = _state_with_stored({})
        state._can_be_loaded = False
        with pytest.warns(UserWarning):
            state.load()
        assert state.last_library_version == 588
        assert state.last_full_sync == datetime(2026, 10, 1, tzinfo=timezone.utc)

    def test_fields_serialise_to_json(self):
        state = OrklState(
            last_library_version=1,
            last_full_sync=datetime(2026, 10, 1, tzinfo=timezone.utc),
        )
        dumped = state.model_dump(mode="json")
        assert dumped["last_library_version"] == 1
        assert dumped["last_full_sync"].startswith("2026-10-01T00:00:00")
