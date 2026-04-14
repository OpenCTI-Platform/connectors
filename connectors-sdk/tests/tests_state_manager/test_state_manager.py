from datetime import datetime, timezone

import pytest
from connectors_sdk.state_manager.state_manager import ConnectorStateManager
from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel


@pytest.fixture
def dummy_connector_state_manager(mock_opencti_connector_helper):
    """A dummy `ConnectorStateManager` instance for testing purposes."""
    return ConnectorStateManager(helper=mock_opencti_connector_helper)


def test_connector_state_manager_is_pydantic_model():
    """Test that `ConnectorStateManager` is a Pydantic model."""
    # Given: the `ConnectorStateManager` class
    # Then: it should be a subclass of pydantic.BaseModel
    assert issubclass(ConnectorStateManager, BaseModel)


def test_connector_state_manager_has_helper_attribute(dummy_connector_state_manager):
    """Test that `ConnectorStateManager` instance has a `_helper` attribute."""
    # Given: an instance of `ConnectorStateManager`
    # Then: it should have a `_helper` attribute that is an instance of `OpenCTIConnectorHelper`
    assert hasattr(dummy_connector_state_manager, "_helper")
    assert isinstance(dummy_connector_state_manager._helper, OpenCTIConnectorHelper)


def test_connector_state_manager_validates_helper_argument():
    """Test that `ConnectorStateManager` raises a `ValueError` if the `helper` argument is invalid."""
    # Given: an invalid `helper` argument (not an instance of `OpenCTIConnectorHelper`)
    invalid_helper = "not a helper"

    # When: initializing a `ConnectorStateManager` instance with the invalid helper
    # Then: it should raise a `ValueError`
    with pytest.raises(ValueError):
        ConnectorStateManager(helper=invalid_helper)  # type: ignore


def test_connector_state_manager_has_default_values(dummy_connector_state_manager):
    """Test that `ConnectorStateManager` model initializes with default values."""
    # Given: a new instance of `ConnectorStateManager`
    # Then: it should have default values for its fields
    assert dummy_connector_state_manager.last_run is None


def test_connector_state_manager_accepts_valid_input(dummy_connector_state_manager):
    """Test that `ConnectorStateManager` model accepts valid input."""
    # Given: an instance of `ConnectorStateManager`
    # When: setting a valid datetime string to the `last_run` field
    dummy_connector_state_manager.last_run = "2024-01-01T00:00:00Z"

    # Then: the field should be updated with the corresponding datetime object
    assert dummy_connector_state_manager.last_run == datetime(
        2024, 1, 1, tzinfo=timezone.utc
    )


def test_connector_state_manager_rejects_invalid_input(dummy_connector_state_manager):
    """Test that `ConnectorStateManager` model rejects invalid input."""
    # Given: an instance of `ConnectorStateManager`
    # When: setting an invalid value to the `last_run` field
    # Then: pydantic should raise a `ValueError` due to validation error
    with pytest.raises(ValueError):
        dummy_connector_state_manager.last_run = "not a datetime"


def test_connector_state_manager_load(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that `ConnectorStateManager` instance loads state from OpenCTI correctly."""
    # Given: a state stored on OpenCTI
    mock_opencti_connector_helper.get_state.return_value = {
        "last_run": "2024-01-01T00:00:00Z",
        "custom_value": "test",
    }

    # When: loading the state into a `ConnectorStateManager` instance
    dummy_connector_state_manager.load()

    # Then: `OpenCTIConnectorHelper.get_state` method should be called and
    # the `dummy_connector_state_manager` fields should be updated with the loaded state
    mock_opencti_connector_helper.get_state.assert_called_once()
    assert dummy_connector_state_manager.last_run == datetime(
        2024, 1, 1, 0, 0, tzinfo=timezone.utc
    )
    assert dummy_connector_state_manager.custom_value == "test"


def test_connector_state_manager_save(
    dummy_connector_state_manager, mock_opencti_connector_helper
):
    """Test that `ConnectorStateManager` instance saves its fields onto OpenCTI correctly."""
    # Given: an instance of `ConnectorStateManager`
    # When: saving a new `last_run` value to OpenCTI
    dummy_connector_state_manager.last_run = datetime(2024, 1, 1, tzinfo=timezone.utc)
    dummy_connector_state_manager.save()

    # Then: `OpenCTIConnectorHelper.set_state` method should be called with the correct dict and
    # the state should be updated immediately on OpenCTI (`force_ping` called)
    mock_opencti_connector_helper.set_state.assert_called_once_with(
        {"last_run": "2024-01-01T00:00:00Z"}
    )
    mock_opencti_connector_helper.force_ping.assert_called_once()
