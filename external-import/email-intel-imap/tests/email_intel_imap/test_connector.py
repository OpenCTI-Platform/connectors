from unittest.mock import Mock

import pytest
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.connector import Connector
from email_intel_imap.converter import ConnectorConverter


@pytest.fixture(name="connector")
def fixture_connector(
    mocked_helper: Mock, mock_email_intel_imap_config: None
) -> Connector:
    config = ConnectorConfig()
    return Connector(
        config=config,
        helper=mocked_helper,
        converter=ConnectorConverter(config=config, helper=mocked_helper),
        client=ConnectorClient(config=config, helper=mocked_helper),
    )


def test_connector_collect_intelligence_empty(connector: Connector) -> None:
    stix_objects = connector._collect_intelligence()
    assert stix_objects == []
