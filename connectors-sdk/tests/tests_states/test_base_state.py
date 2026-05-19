"""Unit tests for `BaseConnectorState` shared behavior."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.states._base_state import BaseConnectorState
from pydantic import BaseModel, ValidationError


class DummyConnectorState(BaseConnectorState):
    """Concrete test model used to validate base state behaviors."""

    last_run: datetime | None = None
    test_field: str | None = None


@pytest.fixture
def dummy_state(mock_opencti_connector_helper) -> DummyConnectorState:
    """Provide a `BaseConnectorState` subclass attached to a mocked helper."""
    state = DummyConnectorState()
    state.attach_opencti_connector_helper(mock_opencti_connector_helper)
    return state


def test_base_connector_state_is_pydantic_model() -> None:
    """Test that `BaseConnectorState` is a Pydantic model."""
    assert issubclass(BaseConnectorState, BaseModel)


def test_base_connector_state_attach_opencti_connector_helper_initializes_client(
    dummy_state: DummyConnectorState,
) -> None:
    """Test that attaching helper initializes the private state client."""
    assert dummy_state._client is not None


def test_base_connector_state_load_requires_helper() -> None:
    """Test that loading without attached helper raises runtime error."""
    state = DummyConnectorState()
    with pytest.raises(RuntimeError, match="attach_opencti_connector_helper"):
        state.load()


def test_base_connector_state_save_requires_helper() -> None:
    """Test that saving without attached helper raises runtime error."""
    state = DummyConnectorState()
    with pytest.raises(RuntimeError, match="attach_opencti_connector_helper"):
        state.save()


def test_base_connector_state_accepts_valid_assignment(
    dummy_state: DummyConnectorState,
) -> None:
    """Test that assignment uses model casting and validation."""
    dummy_state.last_run = "2024-01-01T00:00:00+00:00"  # type: ignore[assignment]
    assert dummy_state.last_run == datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_base_connector_state_rejects_invalid_assignment(
    dummy_state: DummyConnectorState,
) -> None:
    """Test that invalid assignment is rejected by Pydantic."""
    with pytest.raises(ValidationError):
        dummy_state.last_run = "not a datetime"  # type: ignore[assignment]


def test_base_connector_state_loads_state(
    dummy_state: DummyConnectorState,
    mock_opencti_connector_helper,
) -> None:
    """Test that state values are loaded from OpenCTI."""
    mock_opencti_connector_helper.get_state.return_value = {
        "last_run": "2024-01-01T00:00:00+00:00",
        "test_field": "test",
    }

    dummy_state.load()

    mock_opencti_connector_helper.get_state.assert_called_once()
    assert dummy_state.last_run == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert dummy_state.test_field == "test"


def test_base_connector_state_load_with_force_overwrites_local_changes(
    dummy_state: DummyConnectorState,
    mock_opencti_connector_helper,
) -> None:
    """Test that force-loading bypasses unsaved changes protection."""
    mock_opencti_connector_helper.get_state.return_value = {
        "last_run": "2024-01-01T00:00:00+00:00",
        "test_field": "test",
    }

    dummy_state.load()
    dummy_state.last_run = datetime(2024, 1, 2, tzinfo=timezone.utc)
    dummy_state.test_field = "test2"
    mock_opencti_connector_helper.get_state.reset_mock()

    dummy_state.load(force=True)

    mock_opencti_connector_helper.get_state.assert_called_once()
    assert dummy_state.last_run == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert dummy_state.test_field == "test"


def test_base_connector_state_load_warns_on_potential_unsaved_changes(
    dummy_state: DummyConnectorState,
    mock_opencti_connector_helper,
) -> None:
    """Test that non-forced second load emits warning and does not reload state."""
    mock_opencti_connector_helper.get_state.return_value = {
        "last_run": "2024-01-01T00:00:00+00:00",
        "test_field": "test",
    }

    dummy_state.load()
    dummy_state.last_run = datetime(2024, 1, 2, tzinfo=timezone.utc)
    dummy_state.test_field = "test2"
    mock_opencti_connector_helper.get_state.reset_mock()

    with pytest.warns(UserWarning):
        dummy_state.load()

    mock_opencti_connector_helper.get_state.assert_not_called()
    assert dummy_state.last_run == datetime(2024, 1, 2, tzinfo=timezone.utc)
    assert dummy_state.test_field == "test2"


def test_base_connector_state_load_ignores_private_client_key(
    dummy_state: DummyConnectorState,
    mock_opencti_connector_helper,
) -> None:
    """Test that incoming `_client` key does not override private client attr."""
    mock_opencti_connector_helper.get_state.return_value = {"_client": "invalid"}

    original_client = dummy_state._client
    dummy_state.load(force=True)

    mock_opencti_connector_helper.get_state.assert_called_once()
    assert dummy_state._client is original_client
    assert dummy_state.last_run is None
    assert dummy_state.test_field is None


def test_base_connector_state_save_writes_state_and_forces_ping(
    dummy_state: DummyConnectorState,
    mock_opencti_connector_helper,
) -> None:
    """Test that save writes JSON-serialized state and pings immediately."""
    dummy_state.last_run = datetime(2024, 1, 1, tzinfo=timezone.utc)
    dummy_state.test_field = "test"

    dummy_state.save()

    mock_opencti_connector_helper.set_state.assert_called_once_with(
        {
            "last_run": "2024-01-01T00:00:00+00:00",
            "test_field": "test",
        }
    )
    mock_opencti_connector_helper.force_ping.assert_called_once()


def test_base_connector_state_save_includes_extra_fields(
    dummy_state: DummyConnectorState,
    mock_opencti_connector_helper,
) -> None:
    """Test that save preserves undeclared extra fields from state model."""
    dummy_state.last_run = datetime(2024, 1, 1, tzinfo=timezone.utc)
    dummy_state.test_field = "test"
    dummy_state.extra_field = "any value"  # type: ignore[assignment]

    dummy_state.save()

    mock_opencti_connector_helper.set_state.assert_called_once_with(
        {
            "last_run": "2024-01-01T00:00:00+00:00",
            "test_field": "test",
            "extra_field": "any value",
        }
    )
    mock_opencti_connector_helper.force_ping.assert_called_once()
