from typing import Any
from unittest.mock import call

import freezegun
import pytest
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture
from threatmatch.connector import Connector


@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_config(
    mocked_helper: OpenCTIConnectorHelper, config_dict: dict[str, Any]
) -> None:
    connector = Connector()

    assert connector.threatmatch_url == "https://threatmatch-url"
    assert connector.threatmatch_client_id == "threatmatch-client-id"
    assert connector.threatmatch_client_secret == "threatmatch-client-secret"
    assert connector.threatmatch_interval == 1
    assert connector.threatmatch_import_from_date == "2025-01-01 00:00"
    assert connector.threatmatch_import_profiles == True
    assert connector.threatmatch_import_alerts == True
    assert connector.threatmatch_import_iocs == True


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_run(mocked_helper: MockerFixture) -> None:
    connector = Connector()
    with pytest.raises(SystemExit):
        connector.run()
    assert connector.helper.log_info.call_count == 6
    connector.helper.log_info.assert_has_calls(
        [
            call("Fetching ThreatMatch..."),
            call("Connector has never run"),
            call("Connector will run!"),
            call("Connector successfully run, storing last_run as 1744903440"),
            call("Last_run stored, next run in: 1.0 minutes"),
            call("Connector stop"),
        ]
    )
