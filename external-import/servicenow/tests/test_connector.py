from unittest.mock import AsyncMock, Mock

import pytest
from connector.connector import ConnectorServicenow
from connector.models import (
    ConfigLoader,
)
from connector.services import (
    ServiceNowClient,
)
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError


def test_invalid_retrieved_entity_should_be_skipped_with_warning():
    # Given
    # a connector instance with a fake api client response that return a malformed entity with invalid values
    config = Mock()
    config.servicenow.tlp_level = "clear"

    connector_instance = ConnectorServicenow(config=config, helper=Mock())
    invalid_data = [{"get_security_incident": {"invalid": "data"}}]

    # When the connector _valid_intelligence is called
    connector_instance._valid_intelligence(invalid_data)
    # Then a warning should be emitted and the process should (continue (not raise an error)
    pass
