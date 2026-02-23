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

    return mock_helper
