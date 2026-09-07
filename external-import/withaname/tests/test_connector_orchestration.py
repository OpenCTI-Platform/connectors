from unittest.mock import MagicMock, call, patch

import pytest
from connector.connector import WithanameConnector


class TestWithanameConnectorOrchestration:
    @pytest.fixture
    def mock_helper(self):
        helper = MagicMock()
        helper.connect_name = "DDoSIA Connector"
        helper.connect_id = "withaname-id"
        helper.api = MagicMock()
        helper.connector_logger = MagicMock()
        return helper

    @pytest.fixture
    def mock_config(self):
        config = MagicMock()
        config.withaname.api_base_url = "http://api.witha.name"
        config.withaname.tlp_level = "green"
        config.withaname.import_start_timestamp = None
        config.withaname.create_notes = True
        config.connector.duration_period.total_seconds.return_value = 3600
        return config

    @pytest.fixture
    def connector(self, mock_config, mock_helper):
        with patch("connector.connector.WithanameClient"), patch(
            "connector.connector.ConverterToStix"
        ):
            conn = WithanameConnector(mock_config, mock_helper)
            conn.client = MagicMock()
            conn.converter_to_stix = MagicMock()
            return conn

    # --- Pagination Tests ---

    def test_process_message_pagination_full(self, connector, mock_helper):
        """Test that pagination continues until an empty page is reached."""
        connector.config.withaname.import_start_timestamp = 0
        # Page 1: data, Page 2: data, Page 3: empty
        connector.client.get_configs.side_effect = [
            {"items": [{"id": "c1", "ts": "100"}]},
            {"items": [{"id": "c2", "ts": "200"}]},
            {"items": []},
        ]
        # Mock _select_configs_to_process to return all
        connector._select_configs_to_process = MagicMock(
            return_value=[{"id": "c1"}, {"id": "c2"}]
        )
        # Mock _process_snapshot to return empty list to avoid further calls
        connector._process_snapshot = MagicMock(return_value=[])

        connector.process_message()

        assert connector.client.get_configs.call_count == 3
        connector.client.get_configs.assert_has_calls(
            [
                call(page=1),
                call(page=2),
                call(page=3),
            ]
        )

    def test_process_message_pagination_optimization_start_ts(self, connector):
        """Test that pagination stops when last item is older than start_ts."""
        connector.config.withaname.import_start_timestamp = 500
        # Page 1: last item is 400 (<<  500)
        connector.client.get_configs.return_value = {
            "items": [{"id": "c1", "ts": "600"}, {"id": "c2", "ts": "400"}]
        }
        connector._select_configs_to_process = MagicMock(return_value=[])

        connector.process_message()

        # Should stop after page 1
        assert connector.client.get_configs.call_count == 1

    def test_process_message_pagination_none_start_ts(self, connector):
        """Test that pagination stops after page 1 when start_ts is None."""
        connector.config.withaname.import_start_timestamp = None
        connector.client.get_configs.return_value = {
            "items": [{"id": "c1", "ts": "100"}]
        }
        connector._select_configs_to_process = MagicMock(return_value=[])

        connector.process_message()

        assert connector.client.get_configs.call_count == 1

    # --- Snapshot Processing Tests ---

    def test_process_snapshot_success(self, connector, mock_helper):
        """Test successful conversion of a snapshot with targets."""
        config_item = {"id": "cfg_1", "ts": "100"}
        connector.client.get_config.return_value = {
            "targets": [
                {"host": "host1", "ip": "1.1.1.1"},
                {"host": "host1", "ip": "1.1.1.2"},
            ]
        }

        # Mock converter outputs
        mock_obj = MagicMock()
        mock_obj.to_stix2_object.return_value.serialize.return_value = (
            '{"id": "stix_obj"}'
        )
        connector.converter_to_stix.create_domain.return_value = mock_obj
        connector.converter_to_stix.create_ipv4.return_value = mock_obj
        connector.converter_to_stix.create_resolves_to_relationship.return_value = (
            mock_obj
        )
        connector.converter_to_stix.create_note_for_host.return_value = mock_obj

        results = connector._process_snapshot(config_item)

        assert len(results) > 0
        connector.converter_to_stix.create_domain.assert_called_once()
        assert connector.converter_to_stix.create_ipv4.call_count == 2
        connector.converter_to_stix.create_note_for_host.assert_called_once()

    def test_process_snapshot_empty(self, connector, mock_helper):
        """Test that an empty snapshot returns an empty list."""
        config_item = {"id": "cfg_empty", "ts": "100"}
        connector.client.get_config.return_value = {"targets": []}

        results = connector._process_snapshot(config_item)

        assert results == []
        connector.helper.connector_logger.info.assert_any_call(
            "[CONNECTOR] Snapshot cfg_empty is empty", {"cfg_id": "cfg_empty"}
        )

    def test_process_snapshot_no_notes(self, connector):
        """Test that notes are not created when disabled in config."""
        connector.config.withaname.create_notes = False
        config_item = {"id": "cfg_1", "ts": "100"}
        connector.client.get_config.return_value = {
            "targets": [{"host": "h1", "ip": "1.1.1.1"}]
        }

        mock_obj = MagicMock()
        mock_obj.to_stix2_object.return_value.serialize.return_value = "{}"
        connector.converter_to_stix.create_domain.return_value = mock_obj
        connector.converter_to_stix.create_ipv4.return_value = mock_obj
        connector.converter_to_stix.create_resolves_to_relationship.return_value = (
            mock_obj
        )

        connector._process_snapshot(config_item)

        connector.converter_to_stix.create_note_for_host.assert_not_called()

    # --- Orchestration and Resilience Tests ---

    def test_process_message_full_cycle_success(self, connector, mock_helper):
        """Test the full successful flow from pagination to state update."""
        connector.client.get_configs.return_value = {
            "items": [{"id": "cfg_1", "ts": "100"}]
        }
        connector._select_configs_to_process = MagicMock(
            return_value=[{"id": "cfg_1", "ts": "100"}]
        )
        connector._process_snapshot = MagicMock(return_value=[{"id": "stix_1"}])

        mock_work_id = "work_123"
        mock_helper.api.work.initiate_work.return_value = mock_work_id

        connector.process_message()

        mock_helper.api.work.initiate_work.assert_called_once()
        mock_helper.stix2_create_bundle = MagicMock()  # helper method
        # Note: helper.stix2_create_bundle is called via helper, not connector
        # In the real code: bundle = self.helper.stix2_create_bundle(stix_objects)
        # Since we mock helper, we check if the call happened
        mock_helper.send_stix2_bundle.assert_called_once()
        mock_helper.api.work.to_processed.assert_called_with(
            mock_work_id, "Processed snapshot cfg_1 with 1 objects"
        )
        mock_helper.set_state.assert_called_once()

    def test_process_message_isolated_error(self, connector, mock_helper):
        """Test that an error in one snapshot doesn't stop others and doesn't update state."""
        connector.client.get_configs.return_value = {
            "items": [{"id": "c1", "ts": "100"}, {"id": "c2", "ts": "200"}]
        }
        connector._select_configs_to_process = MagicMock(
            return_value=[{"id": "c1", "ts": "100"}, {"id": "c2", "ts": "200"}]
        )

        # First snapshot fails, second succeeds
        connector._process_snapshot = MagicMock(
            side_effect=[Exception("API Error"), [{"id": "stix_2"}]]
        )

        mock_helper.api.work.initiate_work.side_effect = ["work_1", "work_2"]

        connector.process_message()

        # Check that both were attempted
        assert connector._process_snapshot.call_count == 2
        # Check that work_1 was marked as failed
        mock_helper.api.work.to_processed.assert_any_call(
            "work_1", "Failed to process snapshot c1: API Error"
        )
        # Check that work_2 was marked as processed
        mock_helper.api.work.to_processed.assert_any_call(
            "work_2", "Processed snapshot c2 with 1 objects"
        )
        # State should only be updated for the last successful one
        # The code updates state inside the loop after each successful snapshot
        assert mock_helper.set_state.call_count == 1
        # Verify the last state update was for c2
        args, _ = mock_helper.set_state.call_args
        assert args[0]["last_cfg_id"] == "c2"
