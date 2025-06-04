from unittest.mock import MagicMock, Mock

import pytest
from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel.config import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from src.microsoft_sentinel_intel import Connector


@pytest.fixture(name="connector")
def fixture_connector(mocked_api_client: MagicMock) -> Connector:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.model_dump_pycti())
    return Connector(helper=helper, config=config, client=Mock())


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_process_message(connector: Connector) -> None:
    # Ensure there s no error running process_message
    connector.process_message(Event())
