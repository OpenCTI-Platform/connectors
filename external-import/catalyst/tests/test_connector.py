from unittest.mock import Mock, patch

import pytest
from catalyst import CatalystConnector


@pytest.mark.usefixtures("setup_config")
class TestCatalystConnector:
    """Tests for the CatalystConnector class"""

    def setup_method(self):
        """Set up test environment before each test"""
        # Mock the ConfigConnector and OpenCTIConnectorHelper classes
        self.mock_config_patch = patch("catalyst.connector.ConfigConnector")
        self.mock_config_class = self.mock_config_patch.start()
        self.mock_config = Mock()
        self.mock_config_class.return_value = self.mock_config

        self.mock_helper_patch = patch("catalyst.connector.OpenCTIConnectorHelper")
        self.mock_helper_class = self.mock_helper_patch.start()
        self.mock_helper = Mock()
        self.mock_helper_class.return_value = self.mock_helper

        # Mock ConnectorClient
        self.mock_client_patch = patch("catalyst.connector.ConnectorClient")
        self.mock_client_class = self.mock_client_patch.start()
        self.mock_client = Mock()
        self.mock_client_class.return_value = self.mock_client

        # Create an instance of the connector
        self.connector = CatalystConnector()

        # Setup logger
        self.mock_logger = Mock()
        self.mock_helper.connector_logger = self.mock_logger

    def teardown_method(self):
        """Clean up after each test"""
        self.mock_config_patch.stop()
        self.mock_helper_patch.stop()
        self.mock_client_patch.stop()

    def test_initialization(self):
        """Test connector initialization"""
        # Check that ConfigConnector was created
        self.mock_config_class.assert_called_once()

        # Check that OpenCTIConnectorHelper was created with the correct config
        self.mock_helper_class.assert_called_once_with(self.mock_config.load)

        # Check that ConnectorClient was created with the correct parameters
        self.mock_client_class.assert_called_once_with(
            self.mock_helper, self.mock_config
        )

    def test_collect_intelligence_success(
        self, sample_stix_object_report, sample_stix_object_indicator
    ):
        """Test successful intelligence collection with sample StixObject instances"""
        mock_stix_objects = [sample_stix_object_report, sample_stix_object_indicator]

        self.mock_client.get_entities.return_value = mock_stix_objects

        result = self.connector._collect_intelligence()

        assert len(result) == 2
        assert mock_stix_objects[0] in result
        assert mock_stix_objects[1] in result

        self.mock_logger.debug.assert_any_call(
            f"Received entities: {mock_stix_objects}"
        )
        self.mock_logger.debug.assert_any_call(
            f"Adding STIX object of type: {mock_stix_objects[0].type}"
        )
        self.mock_logger.debug.assert_any_call(
            f"Adding STIX object of type: {mock_stix_objects[1].type}"
        )

    def test_collect_intelligence_dict_error(self):
        """Test collection with dictionary entity (should raise error)"""
        self.mock_client.get_entities.return_value = [{"type": "indicator"}]

        with pytest.raises(ValueError, match="Unexpected entity type"):
            self.connector._collect_intelligence()

        self.mock_logger.error.assert_called_once()

    def test_collect_intelligence_invalid_type(self):
        """Test collection with invalid entity type (should warn)"""
        invalid_entity = 123  # Not a STIX object or dict
        self.mock_client.get_entities.return_value = [invalid_entity]

        result = self.connector._collect_intelligence()

        # Verify warning is logged and no objects returned
        assert len(result) == 0
        self.mock_logger.warning.assert_called_once_with(
            f"Unexpected entity type: {type(invalid_entity)}. Expected a STIX object or dictionary."
        )

    def test_process_message_first_run(self, mock_opencti_helper):
        """Test process_message on first run (no previous state)"""
        self.mock_helper = mock_opencti_helper
        self.connector.helper = mock_opencti_helper

        # Mock get_state to return None (no previous state)
        mock_opencti_helper.get_state.return_value = None

        mock_work_id = "work-id-123"
        mock_opencti_helper.api.work.initiate_work.return_value = mock_work_id

        mock_stix_objects = [Mock(), Mock()]
        with patch.object(
            self.connector, "_collect_intelligence", return_value=mock_stix_objects
        ):
            mock_bundle = "stix-bundle-123"
            mock_opencti_helper.stix2_create_bundle.return_value = mock_bundle
            mock_opencti_helper.send_stix2_bundle.return_value = ["bundle-sent"]

            self.connector.process_message()

            mock_opencti_helper.set_state.assert_called_once()

            mock_opencti_helper.stix2_create_bundle.assert_called_once_with(
                mock_stix_objects
            )
            mock_opencti_helper.send_stix2_bundle.assert_called_once_with(
                mock_bundle, work_id=mock_work_id, cleanup_inconsistent_bundle=True
            )

            mock_opencti_helper.api.work.to_processed.assert_called_once()

    def test_process_message_subsequent_run(self, mock_opencti_helper):
        """Test process_message on subsequent runs (with previous state)"""
        self.mock_helper = mock_opencti_helper
        self.connector.helper = mock_opencti_helper

        # Mock get_state to return previous state
        previous_state = {"last_run": "2023-01-01 00:00:00"}
        mock_opencti_helper.get_state.return_value = previous_state

        mock_work_id = "work-id-123"
        mock_opencti_helper.api.work.initiate_work.return_value = mock_work_id

        mock_stix_objects = [Mock(), Mock()]
        with patch.object(
            self.connector, "_collect_intelligence", return_value=mock_stix_objects
        ):
            mock_bundle = "stix-bundle-123"
            mock_opencti_helper.stix2_create_bundle.return_value = mock_bundle
            mock_opencti_helper.send_stix2_bundle.return_value = ["bundle-sent"]

            self.connector.process_message()

            # Verify previous state is logged
            mock_opencti_helper.connector_logger.info.assert_any_call(
                "[CONNECTOR] Connector last run",
                {"last_run_datetime": "2023-01-01 00:00:00"},
            )

            # Verify state is updated
            mock_opencti_helper.set_state.assert_called_once()

            # Verify bundle is created and sent
            mock_opencti_helper.stix2_create_bundle.assert_called_once_with(
                mock_stix_objects
            )
            mock_opencti_helper.send_stix2_bundle.assert_called_once_with(
                mock_bundle, work_id=mock_work_id, cleanup_inconsistent_bundle=True
            )

    def test_process_message_no_stix_objects(self, mock_opencti_helper):
        """Test process_message when no STIX objects are collected"""
        self.mock_helper = mock_opencti_helper
        self.connector.helper = mock_opencti_helper

        mock_opencti_helper.get_state.return_value = None

        mock_work_id = "work-id-123"
        mock_opencti_helper.api.work.initiate_work.return_value = mock_work_id

        with patch.object(self.connector, "_collect_intelligence", return_value=[]):
            self.connector.process_message()

            mock_opencti_helper.stix2_create_bundle.assert_not_called()
            mock_opencti_helper.send_stix2_bundle.assert_not_called()

            # Verify state is still updated
            mock_opencti_helper.set_state.assert_called_once()

    def test_process_message_exception(self, mock_opencti_helper):
        """Test process_message handling of exceptions"""
        self.mock_helper = mock_opencti_helper
        self.connector.helper = mock_opencti_helper

        mock_opencti_helper.get_state.side_effect = Exception("Test error")

        self.connector.process_message()

        # Verify error is logged
        mock_opencti_helper.connector_logger.error.assert_called_once_with("Test error")

    def test_run(self, mock_config):
        """Test the run method using the mock_config fixture"""
        self.mock_config = mock_config
        self.connector.config = mock_config

        mock_config.duration_period = "P1D"

        self.connector.run()

        self.mock_helper.schedule_iso.assert_called_once_with(
            message_callback=self.connector.process_message,
            duration_period=mock_config.duration_period,
        )
