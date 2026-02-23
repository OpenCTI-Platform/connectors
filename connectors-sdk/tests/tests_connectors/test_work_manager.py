import pytest
import stix2

from connectors_sdk.connectors._work_manager import WorkManager
from connectors_sdk.models import OrganizationAuthor, Indicator


@pytest.fixture
def dummy_work_manager(mock_opencti_connector_helper):
    """A dummy WorkManager for testing purposes."""
    return WorkManager(helper=mock_opencti_connector_helper)


def test_work_manager_init_work(dummy_work_manager, mock_opencti_connector_helper):
    """Test that the WorkManager initiates work correctly."""
    work_id = dummy_work_manager.init_work(name="Test work")

    assert work_id == "test_work_id"

    mock_opencti_connector_helper.api.work.initiate_work.assert_called_once_with(
        connector_id="test_connector_id",
        friendly_name="Test work",
    )


def test_work_manager_send_bundle(dummy_work_manager, mock_opencti_connector_helper):
    """Test that the WorkManager sends a STIX bundle correctly."""
    work_id = "test_work_id"
    author = OrganizationAuthor(name="Test Author")
    indicator = Indicator(
        name="test.com",
        pattern="[url:value = 'test.com']",
        pattern_type="stix",
        author=author,
    )
    stix_objects = [author, indicator]

    stix_bundle = stix2.Bundle(
        objects=[obj.to_stix2_object() for obj in stix_objects],
        allow_custom=True,
    )
    mock_opencti_connector_helper.stix2_create_bundle.return_value = stix_bundle

    dummy_work_manager.send_bundle(work_id=work_id, stix_objects=stix_objects)

    mock_opencti_connector_helper.stix2_create_bundle.assert_called_once_with(
        stix_objects
    )
    mock_opencti_connector_helper.send_stix2_bundle.assert_called_once_with(
        bundle=stix_bundle,
        work_id=work_id,
    )


def test_work_manager_complete_work(dummy_work_manager, mock_opencti_connector_helper):
    """Test that the WorkManager marks work as completed correctly."""
    work_id = "test_work_id"
    message = "Work completed successfully"
    in_error = False

    dummy_work_manager.complete_work(
        work_id=work_id, message=message, in_error=in_error
    )

    mock_opencti_connector_helper.api.work.to_processed.assert_called_once_with(
        work_id, message, in_error
    )


def test_work_manager_delete_work(dummy_work_manager, mock_opencti_connector_helper):
    """Test that the WorkManager deletes work correctly."""
    work_id = "test_work_id"

    dummy_work_manager.delete_work(work_id=work_id)

    mock_opencti_connector_helper.api.work.delete_work.assert_called_once_with(work_id)
