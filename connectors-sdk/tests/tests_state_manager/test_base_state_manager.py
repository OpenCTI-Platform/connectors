from datetime import datetime, timezone

import pytest

import pytest
from connectors_sdk.state_manager.base_state_manager import BaseConnectorStateManager

from pydantic import BaseModel


@pytest.fixture
def dummy_connector_state_manager(mock_opencti_connector_helper):
    """A dummy connector state manager for testing purposes."""
    return BaseConnectorStateManager(helper=mock_opencti_connector_helper)


def test_base_state_manager_is_pydantic_model():
    """Test that the BaseConnectorStateManager is a Pydantic model."""
    assert issubclass(BaseConnectorStateManager, BaseModel)


def test_base_state_manager_has_default_values(dummy_connector_state_manager):
    """Test that the BaseConnectorStateManager initializes with default values."""
    assert dummy_connector_state_manager.last_run is None
    assert dummy_connector_state_manager._cache is None


def test_base_state_manager_load(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that the BaseConnectorStateManager loads state correctly."""

    mock_opencti_connector_helper.get_state.return_value = {
        "last_run": "2024-01-01T00:00:00Z",
        "custom_value": "test",
    }

    loaded_state = dummy_connector_state_manager.load()

    assert loaded_state.last_run == datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
    assert loaded_state.custom_value == "test"
    assert (
        dummy_connector_state_manager._cache
        == dummy_connector_state_manager.model_copy()
    )


def test_base_state_manager_accepts_valid_input(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that the BaseConnectorStateManager accepts valid input."""
    dummy_connector_state_manager.last_run = "2024-01-01T00:00:00Z"

    assert dummy_connector_state_manager.last_run == datetime(
        2024, 1, 1, tzinfo=timezone.utc
    )


def test_base_state_manager_rejects_invalid_input(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that the BaseConnectorStateManager rejects invalid input."""

    with pytest.raises(ValueError):
        dummy_connector_state_manager.last_run = "not a datetime"


def test_base_state_manager_save(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that the BaseConnectorStateManager saves state correctly."""
    dummy_connector_state_manager.last_run = datetime(2024, 1, 1, tzinfo=timezone.utc)
    dummy_connector_state_manager.save()

    mock_opencti_connector_helper.set_state.assert_called_once_with(
        {"last_run": "2024-01-01T00:00:00Z"}
    )
    assert (
        dummy_connector_state_manager._cache
        == dummy_connector_state_manager.model_copy()
    )


def test_base_state_manager_clear_cache(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that the BaseConnectorStateManager clears cache correctly."""

    mock_opencti_connector_helper.get_state.return_value = {
        "last_run": "2024-01-01T00:00:00Z",
    }

    dummy_connector_state_manager.load()

    assert (
        dummy_connector_state_manager._cache
        == dummy_connector_state_manager.model_copy()
    )

    dummy_connector_state_manager.clear_cache()

    assert dummy_connector_state_manager._cache is None
