from unittest.mock import MagicMock, Mock

import pytest
from filigran_sseclient.sseclient import Event
from src.microsoft_sentinel_intel_connector import MicrosoftSentinelIntelConnector


@pytest.fixture(name="connector")
def fixture_connector(mocked_helper: MagicMock) -> MicrosoftSentinelIntelConnector:
    return MicrosoftSentinelIntelConnector(
        helper=mocked_helper, config=Mock(), client=Mock()
    )


def test_process_message(connector: MicrosoftSentinelIntelConnector) -> None:
    # Ensure there s no error running process_message
    connector.process_message(Event())
