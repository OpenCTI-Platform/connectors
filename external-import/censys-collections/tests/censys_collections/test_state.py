"""Tests for censys_collections.state."""

from datetime import datetime, timezone

from censys_collections.state import CensysCollectionsState


def test_state_defaults_to_no_checkpoints() -> None:
    state = CensysCollectionsState()
    assert state.collection_checkpoints == {}
    assert state.last_run is None


def test_state_checkpoints_round_trip_through_json() -> None:
    checkpoint = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)
    state = CensysCollectionsState(collection_checkpoints={"coll-1": checkpoint})

    restored = CensysCollectionsState.model_validate(state.to_json())

    assert restored.collection_checkpoints == {"coll-1": checkpoint}
