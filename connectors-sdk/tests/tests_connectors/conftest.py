from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk import BaseConnectorSettings
from pycti import OpenCTIConnectorHelper


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

    # Mock config vars
    mock_helper.connect_name = "Test Connector"
    mock_helper.connect_id = "test_connector_id"
    mock_helper.log_level = "debug"

    # Mock logger
    mock_helper.connector_logger = MagicMock()
    mock_helper.connector_logger.debug = MagicMock()
    mock_helper.connector_logger.info = MagicMock()
    mock_helper.connector_logger.warning = MagicMock()
    mock_helper.connector_logger.error = MagicMock()

    # Mock the connector's state management methods
    mock_helper.get_state.return_value = {"test_key": "test_value"}
    mock_helper.set_state = MagicMock()

    # Mock the work API for WorkManager tests
    mock_helper.api = MagicMock()
    mock_helper.api.work = MagicMock()
    mock_helper.api.work.initiate_work.return_value = "test_work_id"
    mock_helper.api.work.to_processed.return_value = None
    mock_helper.api.work.delete_work.return_value = None

    return mock_helper
