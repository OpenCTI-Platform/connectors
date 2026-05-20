# pragma: no cover
# type: ignore
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.external_import.logger import ConnectorLogger


@pytest.fixture
def mock_helper() -> MagicMock:
    """Mock OpenCTIConnectorHelper with all required attributes."""
    helper = MagicMock()
    helper.connect_id = "test-connector-id"
    helper.connect_name = "Test Connector"
    helper.connector_logger = MagicMock()
    helper.api.work.initiate_work.return_value = "work-123"
    helper.api.work.to_processed.return_value = None
    helper.api.work.delete.return_value = None
    helper.stix2_create_bundle.return_value = '{"type": "bundle", "objects": []}'
    helper.send_stix2_bundle.return_value = ["bundle-1"]
    helper.schedule_process.return_value = None
    helper.get_state.return_value = {}
    helper.set_state.return_value = None
    helper.force_ping.return_value = None
    return helper


@pytest.fixture
def mock_logger(mock_helper: MagicMock) -> ConnectorLogger:
    """ConnectorLogger backed by mock helper."""
    return ConnectorLogger(mock_helper)


@pytest.fixture
def mock_config() -> MagicMock:
    """Mock BaseConnectorSettings with required attributes."""
    config = MagicMock()
    config.connector.name = "Test Connector"
    config.connector.duration_period = timedelta(hours=1)
    config.to_helper_config.return_value = {}
    return config
