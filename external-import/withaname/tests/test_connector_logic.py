from unittest.mock import MagicMock

import pytest
from connector.connector import WithanameConnector


class TestSelectConfigsToProcess:
    @pytest.fixture
    def mock_helper(self):
        return MagicMock()

    @pytest.fixture
    def mock_config(self):
        # We use a simple MagicMock without 'spec' to allow dynamic attribute assignment
        # or we can create a mock that specifically has the 'withaname' attribute.
        config = MagicMock()
        config.withaname = MagicMock()
        config.withaname.api_base_url = "http://api.witha.name"
        config.withaname.tlp_level = "green"
        config.withaname.import_start_timestamp = None
        return config

    @pytest.fixture
    def connector(self, mock_config, mock_helper):
        # We need to mock WithanameClient and ConverterToStix to avoid instantiation errors
        with pytest.MonkeyPatch.context() as m:
            m.setattr("connector.connector.WithanameClient", MagicMock)
            m.setattr("connector.connector.ConverterToStix", MagicMock)
            return WithanameConnector(mock_config, mock_helper)

    @pytest.fixture
    def sample_configs(self):
        return [
            {"id": "cfg_1", "ts": "100.0"},
            {"id": "cfg_3", "ts": "300.0"},
            {"id": "cfg_2", "ts": "200.0"},
        ]

    def test_select_configs_first_run_no_timestamp(self, connector, sample_configs):
        """Default behavior: only the most recent snapshot if no state and no start_ts."""
        connector.config.withaname.import_start_timestamp = None
        state = None

        result = connector._select_configs_to_process(sample_configs, state)

        assert len(result) == 1
        assert result[0]["id"] == "cfg_3"  # The one with ts 300.0

    def test_select_configs_first_run_all_history(self, connector, sample_configs):
        """If import_start_timestamp is 0, import all available history."""
        connector.config.withaname.import_start_timestamp = 0
        state = None

        result = connector._select_configs_to_process(sample_configs, state)

        assert len(result) == 3
        assert result[0]["id"] == "cfg_1"  # Sorted ascending
        assert result[1]["id"] == "cfg_2"
        assert result[2]["id"] == "cfg_3"

    def test_select_configs_first_run_with_timestamp(self, connector, sample_configs):
        """If import_start_timestamp > 0, import from that timestamp onwards."""
        connector.config.withaname.import_start_timestamp = 150.0
        state = None

        result = connector._select_configs_to_process(sample_configs, state)

        assert len(result) == 2
        assert result[0]["id"] == "cfg_2"
        assert result[1]["id"] == "cfg_3"

    def test_select_configs_incremental_import(self, connector, sample_configs):
        """Incremental import: only those strictly newer than last_cfg_ts."""
        state = {"last_cfg_ts": 200.0}

        result = connector._select_configs_to_process(sample_configs, state)

        assert len(result) == 1
        assert result[0]["id"] == "cfg_3"

    def test_select_configs_empty_list(self, connector):
        """Handle empty configuration list."""
        result = connector._select_configs_to_process([], None)
        assert result == []

    def test_select_configs_invalid_timestamps(self, connector):
        """Handle cases where timestamps might be missing or invalid.
        They should be treated as 0.0 and sorted accordingly.
        """
        configs = [
            {"id": "cfg_1", "ts": "100.0"},
            {"id": "cfg_err", "ts": None},  # Should be treated as 0.0
            {"id": "cfg_bad", "ts": "invalid"},  # Should be treated as 0.0
        ]
        state = None
        connector.config.withaname.import_start_timestamp = 0

        result = connector._select_configs_to_process(configs, state)

        # Sorted: cfg_err (0.0), cfg_bad (0.0), cfg_1 (100.0)
        # Note: stable sort preserves relative order of items with same key
        assert len(result) == 3
        assert result[0]["id"] in ["cfg_err", "cfg_bad"]
        assert result[1]["id"] in ["cfg_err", "cfg_bad"]
        assert result[2]["id"] == "cfg_1"
