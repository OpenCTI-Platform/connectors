import datetime

import pytest
from pydantic import HttpUrl
from shadowserver.config import ConnectorSettings


@pytest.mark.usefixtures("mock_config")
def test_config() -> None:
    config = ConnectorSettings().model_dump()

    assert config["opencti"]["url"] == HttpUrl("http://test-opencti-url/")
    assert config["opencti"]["token"] == "ChangeMe"

    assert config["connector"]["id"] == "ChangeMe"
    assert config["connector"]["name"] == "Shadowserver"
    assert config["connector"]["scope"] == ["stix2"]
    assert config["connector"]["duration_period"] == datetime.timedelta(days=1)
    assert config["connector"]["run_every"] == "2d"

    assert len(config["shadowserver"]) == 6
    assert config["shadowserver"]["api_key"] == "CHANGEME"
    assert config["shadowserver"]["api_secret"] == "CHANGEME"
    assert config["shadowserver"]["marking"] == "TLP:CLEAR"
    assert config["shadowserver"]["create_incident"] == True
    assert config["shadowserver"]["incident_severity"] == "high"
    assert config["shadowserver"]["incident_priority"] == "P1"
