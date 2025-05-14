import datetime
import os

import pytest
from lib.base_connector_config import ConfigRetrievalError
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
    assert config["connector"]["duration_period"] == datetime.timedelta(days=2)

    assert len(config["shadowserver"]) == 6
    assert config["shadowserver"]["api_key"] == "CHANGEME"
    assert config["shadowserver"]["api_secret"] == "CHANGEME"
    assert config["shadowserver"]["marking"] == "TLP:CLEAR"
    assert config["shadowserver"]["create_incident"] == True
    assert config["shadowserver"]["incident_severity"] == "high"
    assert config["shadowserver"]["incident_priority"] == "P1"


@pytest.mark.usefixtures("mock_config")
def test_config_run_every_deprecated(recwarn: pytest.WarningsRecorder) -> None:
    # Assert warning is not raised when run_every is not set
    ConnectorSettings().model_dump()
    assert len(recwarn) == 0

    os.environ["CONNECTOR_RUN_EVERY"] = "3d"

    # Assert run_every and duration_period are mutually exclusive
    with pytest.raises(ConfigRetrievalError):
        ConnectorSettings().model_dump()

    os.environ.pop("CONNECTOR_DURATION_PERIOD")
    config = ConnectorSettings().model_dump()

    # Assert run_every is deprecated and the warning is raised
    assert recwarn[0].category == UserWarning
    assert recwarn[0].message.args == (
        "CONNECTOR_RUN_EVERY is deprecated. Use CONNECTOR_DURATION_PERIOD instead.",
    )

    assert config["connector"]["duration_period"] == datetime.timedelta(days=3)
