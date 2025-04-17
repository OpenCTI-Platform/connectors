from unittest.mock import Mock

import pytest
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_client(mocked_helper: Mock):
    client = ConnectorClient(config=ConnectorConfig(), helper=mocked_helper)
    assert client
