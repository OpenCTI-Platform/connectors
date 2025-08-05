from unittest.mock import call

import freezegun
import pytest
from pydantic_settings import SettingsConfigDict
from pytest_mock import MockerFixture
from threatmatch.config import ConnectorSettings
from threatmatch.connector import Connector


class _ConnectorSettings(ConnectorSettings):
    model_config = SettingsConfigDict(yaml_file="")


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_run(mocked_helper: MockerFixture) -> None:
    connector = Connector(helper=mocked_helper, config=_ConnectorSettings())
    with pytest.raises(SystemExit):
        connector.run()
    assert connector.helper.connector_logger.info.call_count == 6
    connector.helper.connector_logger.info.assert_has_calls(
        [
            call("Fetching ThreatMatch..."),
            call("Connector has never run"),
            call("Connector will run!"),
            call("Connector successfully run, storing last_run as 1744903440"),
            call("Last_run stored, next run in: 1.0 minutes"),
            call("Connector stop"),
        ]
    )
