"""Unit tests for concrete state subclasses."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.states._base_state import BaseConnectorState
from connectors_sdk.states.states import ExternalImportConnectorState
from pydantic import ValidationError


@pytest.fixture
def external_import_state(mock_opencti_connector_helper):
    """An attached `ExternalImportConnectorState` instance for tests."""
    state = ExternalImportConnectorState()
    state.attach_opencti_connector_helper(mock_opencti_connector_helper)
    return state


def test_external_import_connector_state_inherits_from_base() -> None:
    """Test that `ExternalImportConnectorState` is a `BaseConnectorState` subclass."""
    assert issubclass(ExternalImportConnectorState, BaseConnectorState)


def test_external_import_connector_state_has_default_values(
    external_import_state: ExternalImportConnectorState,
) -> None:
    """Test that subclass fields are initialized with expected defaults."""
    assert external_import_state.last_run is None


def test_external_import_connector_state_accepts_valid_last_run_assignment(
    external_import_state: ExternalImportConnectorState,
) -> None:
    """Test that a valid ISO datetime is parsed on assignment."""
    external_import_state.last_run = "2024-01-01T00:00:00+00:00"  # type: ignore[assignment]
    assert external_import_state.last_run == datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_external_import_connector_state_rejects_invalid_last_run_assignment(
    external_import_state: ExternalImportConnectorState,
) -> None:
    """Test that invalid datetime values are rejected on assignment."""
    with pytest.raises(ValidationError):
        external_import_state.last_run = "not a datetime"  # type: ignore[assignment]
