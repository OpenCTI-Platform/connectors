from typing import Any
from unittest.mock import MagicMock

import freezegun
import pytest
import stix2.base
import stix2.utils
from connectors_sdk import BaseConnectorStateManager
from connectors_sdk.connectors._work_manager import WorkManager, WorkManagerError
from connectors_sdk.connectors.base_data_processor import BaseDataProcessor
from connectors_sdk.models import Indicator, OrganizationAuthor

FROZEN_ISO_DATETIME = "2026-01-01T00:00:00Z"


@pytest.fixture
def dummy_connector_state_manager(mock_opencti_connector_helper):
    """A dummy connector state manager for testing purposes."""
    return BaseConnectorStateManager(helper=mock_opencti_connector_helper)


@pytest.fixture
def dummy_data_processor(
    dummy_connector_settings,
    mock_opencti_connector_helper,
    dummy_connector_state_manager,
):
    """A dummy data processor for testing purposes."""

    class DummyDataProcessor(BaseDataProcessor):
        """A dummy implementation of BaseDataProcessor for testing purposes."""

        def collect(self) -> Any:
            return [{"name": "test.com", "value": "test.com"}]

        def transform(self, data: Any) -> Any:
            author = OrganizationAuthor(name="Test Author")
            indicator = Indicator(
                name="test.com",
                pattern="[url:value = 'test.com']",
                pattern_type="stix",
                author=author,
            )
            return [author, indicator]

    return DummyDataProcessor(
        config=dummy_connector_settings,
        helper=mock_opencti_connector_helper,
        state_manager=dummy_connector_state_manager,
    )


@pytest.fixture
def freeze_stix_timestamps(monkeypatch):
    """Freeze STIX internal timestamp generation for deterministic tests."""
    frozen_timestamp = stix2.utils.parse_into_datetime(FROZEN_ISO_DATETIME)
    monkeypatch.setattr(stix2.utils, "get_timestamp", lambda: frozen_timestamp)
    monkeypatch.setattr(stix2.base, "get_timestamp", lambda: frozen_timestamp)


def test_base_data_processor_cannot_be_instantiated_directly(
    dummy_connector_settings,
    mock_opencti_connector_helper,
    dummy_connector_state_manager,
):
    """Test that the BaseDataProcessor cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseDataProcessor(
            config=dummy_connector_settings,
            helper=mock_opencti_connector_helper,
            state_manager=dummy_connector_state_manager,
        )


def test_base_data_processor_init_a_work_manager(dummy_data_processor):
    """Test that the BaseDataProcessor initializes the WorkManager correctly."""
    assert isinstance(dummy_data_processor.work_manager, WorkManager)


def test_dummy_data_processor_collect_intelligence(dummy_data_processor):
    """Test the collect method of the DummyDataProcessor."""
    data = dummy_data_processor.collect()

    assert data == [{"name": "test.com", "value": "test.com"}]


def test_dummy_data_processor_transform_intelligence(dummy_data_processor):
    """Test the transform method of the DummyDataProcessor."""
    data = [{"name": "test.com", "value": "test.com"}]

    stix_objects = dummy_data_processor.transform(data)

    assert len(stix_objects) == 2
    assert isinstance(stix_objects[0], OrganizationAuthor)
    assert isinstance(stix_objects[1], Indicator)


@freezegun.freeze_time(FROZEN_ISO_DATETIME)
def test_base_data_processor_complete_work_on_send_intelligence_success(
    dummy_data_processor,
    freeze_stix_timestamps,  # Ensure STIX timestamps are deterministic for this test
):
    """Test the send method of the BaseDataProcessor."""
    work_id = "test_work_id"
    author = OrganizationAuthor(name="Test Author")
    indicator = Indicator(
        name="test.com",
        pattern="[url:value = 'test.com']",
        pattern_type="stix",
        author=author,
    )

    octi_objects = [author, indicator]
    stix_objects = [obj.to_stix2_object() for obj in octi_objects]

    dummy_data_processor.work_manager.init_work = MagicMock(return_value=work_id)
    dummy_data_processor.work_manager.send_bundle = MagicMock()
    dummy_data_processor.work_manager.complete_work = MagicMock()

    dummy_data_processor.send(octi_objects)

    dummy_data_processor.work_manager.init_work.assert_called_once()
    dummy_data_processor.work_manager.send_bundle.assert_called_once_with(
        work_id=work_id,
        stix_objects=stix_objects,
    )
    dummy_data_processor.work_manager.complete_work.assert_called_once_with(
        work_id=work_id,
        message="Work completed successfully",
    )


@freezegun.freeze_time(FROZEN_ISO_DATETIME)
def test_base_data_processor_deletes_work_on_send_intelligence_failure(
    dummy_data_processor,
    freeze_stix_timestamps,  # Ensure STIX timestamps are deterministic for this test
):
    """Test that the BaseDataProcessor deletes the work if sending intelligence fails."""
    work_id = "test_work_id"
    author = OrganizationAuthor(name="Test Author")
    indicator = Indicator(
        name="test.com",
        pattern="[url:value = 'test.com']",
        pattern_type="stix",
        author=author,
    )

    octi_objects = [author, indicator]
    stix_objects = [obj.to_stix2_object() for obj in octi_objects]

    dummy_data_processor.work_manager.init_work = MagicMock(return_value=work_id)
    dummy_data_processor.work_manager.send_bundle = MagicMock(
        side_effect=WorkManagerError("Failed to send bundle")
    )
    dummy_data_processor.work_manager.delete_work = MagicMock()

    dummy_data_processor.send(octi_objects)

    dummy_data_processor.work_manager.init_work.assert_called_once()
    dummy_data_processor.work_manager.send_bundle.assert_called_once_with(
        work_id=work_id, stix_objects=stix_objects
    )
    dummy_data_processor.work_manager.delete_work.assert_called_once_with(work_id)
