from typing import Any
from unittest.mock import MagicMock


from connectors_sdk.connectors._work_manager import WorkManager
from connectors_sdk.models import OrganizationAuthor, Indicator


import pytest
from connectors_sdk.connectors.base_data_processor import BaseDataProcessor
from connectors_sdk import BaseConnectorSettings, BaseConnectorStateManager


@pytest.fixture
def dummy_connector_settings():
    """A dummy connector settings for testing purposes."""

    class DummyConnectorSettings(BaseConnectorSettings):
        """A dummy implementation of BaseConnectorSettings for testing purposes."""

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:  # type: ignore[override]
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {
                        "id": "connector-id",
                        "name": "Test Connector",
                        "scope": "test, connector",
                        "log_level": "error",
                        "duration_period": "PT5M",
                    },
                    "pouet_pouet": {
                        "api_base_url": "http://test.com",
                        "api_key": "test-api-key",
                        "tlp_level": "clear",
                    },
                }
            )

    return DummyConnectorSettings()


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


def test_base_data_processor_send_intelligence(
    dummy_data_processor, mock_opencti_connector_helper
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
    stix_objects = [author, indicator]

    send_bundle_spy = MagicMock(wraps=dummy_data_processor.work_manager.send_bundle)
    complete_work_spy = MagicMock(wraps=dummy_data_processor.work_manager.complete_work)

    dummy_data_processor.work_manager.init_work = MagicMock(return_value=work_id)
    dummy_data_processor.work_manager.send_bundle = send_bundle_spy
    dummy_data_processor.work_manager.complete_work = complete_work_spy

    dummy_data_processor.send(stix_objects)

    dummy_data_processor.work_manager.init_work.assert_called_once()
    dummy_data_processor.work_manager.send_bundle.assert_called_once()
    dummy_data_processor.work_manager.complete_work.assert_called_once_with(
        work_id=work_id,
        message="Work completed successfully",
    )

    mock_opencti_connector_helper.stix2_create_bundle.assert_called_once_with(
        dummy_data_processor.work_manager.send_bundle.call_args.kwargs["stix_objects"]
    )
    mock_opencti_connector_helper.send_stix2_bundle.assert_called_once_with(
        bundle=mock_opencti_connector_helper.stix2_create_bundle.return_value,
        work_id=work_id,
    )
