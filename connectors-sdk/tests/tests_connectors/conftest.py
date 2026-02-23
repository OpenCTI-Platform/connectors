from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper() -> MagicMock:
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    mock_helper = MagicMock(spec=OpenCTIConnectorHelper)
    mock_helper.killProgramHook = MagicMock()
    mock_helper.sched = MagicMock()
    mock_helper.ConnectorInfo = MagicMock()
    mock_helper.OpenCTIApiClient = MagicMock()
    mock_helper.OpenCTIConnector = MagicMock()
    mock_helper.OpenCTIMetricHandler = MagicMock()
    mock_helper.PingAlive = MagicMock()

    # Mock logger
    mock_helper.connector_logger = MagicMock()
    mock_helper.connector_logger.debug = MagicMock()
    mock_helper.connector_logger.info = MagicMock()
    mock_helper.connector_logger.warning = MagicMock()
    mock_helper.connector_logger.error = MagicMock()

    # Mock the work API for WorkManager tests
    mock_helper.connect_id = "test_connector_id"
    mock_helper.api = MagicMock()
    mock_helper.api.work = MagicMock()
    mock_helper.api.work.initiate_work.return_value = "test_work_id"
    mock_helper.api.work.to_processed.return_value = None
    mock_helper.api.work.delete_work.return_value = None

    return mock_helper
