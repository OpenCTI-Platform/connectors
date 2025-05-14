import os
from unittest.mock import MagicMock

import pytest
from shadowserver.config import ConnectorSettings
from shadowserver.connector import CustomConnector


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization() -> None:
    connector = CustomConnector(helper=MagicMock(), config=ConnectorSettings())

    assert connector.config.shadowserver.api_key == "CHANGEME"
    assert connector.config.shadowserver.api_secret == "CHANGEME"
    assert connector.interval == "2d"
    assert connector.config.shadowserver.marking == "TLP:CLEAR"
    assert connector.config.shadowserver.create_incident == True
    assert connector.config.shadowserver.incident_priority == "P1"
    assert connector.config.shadowserver.incident_severity == "high"


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "create_incident, expected", [("false", False), ("true", True)]
)
def test_connector_initialization_create_incident(create_incident, expected) -> None:
    os.environ["SHADOWSERVER_CREATE_INCIDENT"] = create_incident

    connector = CustomConnector(helper=MagicMock(), config=ConnectorSettings())

    assert connector.config.shadowserver.create_incident == expected
    assert connector.config.shadowserver.incident_priority == "P1"
    assert connector.config.shadowserver.incident_severity == "high"


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization_default_incident() -> None:
    os.environ.pop("SHADOWSERVER_CREATE_INCIDENT")
    os.environ.pop("SHADOWSERVER_INCIDENT_SEVERITY")
    os.environ.pop("SHADOWSERVER_INCIDENT_PRIORITY")

    connector = CustomConnector(helper=MagicMock(), config=ConnectorSettings())

    assert connector.config.shadowserver.create_incident == False
    assert connector.config.shadowserver.incident_priority == "P4"
    assert connector.config.shadowserver.incident_severity == "low"
