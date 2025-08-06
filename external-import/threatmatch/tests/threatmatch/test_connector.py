from unittest.mock import call

import freezegun
import pytest
from pytest_mock import MockerFixture
from threatmatch.config import ConnectorSettings
from threatmatch.connector import Connector


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_run(mocked_helper: MockerFixture) -> None:
    connector = Connector(helper=mocked_helper, config=ConnectorSettings())
    connector.run()
    assert connector.helper.connector_logger.info.call_count == 1
    connector.helper.connector_logger.info.assert_has_calls(
        [call("Fetching ThreatMatch...")]
    )

    assert mocked_helper.schedule_unit.call_count == 1


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_process(mocked_helper: MockerFixture) -> None:
    connector = Connector(helper=mocked_helper, config=ConnectorSettings())
    connector._process()

    assert connector.helper.connector_logger.error.call_count == 1  # Bad url
    assert (
        "HTTPSConnectionPool(host='test-threatmatch-url', port=443): Max retries exceeded with url: /api/developers-platform/token"
        in connector.helper.connector_logger.error.call_args[0][0]
    )
    assert connector.helper.connector_logger.info.call_count == 4
    connector.helper.connector_logger.info.assert_has_calls(
        [
            call("Connector has never run"),
            call("Connector will run!"),
            call("Connector successfully run, storing last_run as 1744903440"),
            call("Last_run stored, next run in: 1.0 minutes"),
        ]
    )
