from datetime import datetime
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
        [call("Connector starting...")]
    )

    assert mocked_helper.schedule_process.call_count == 1


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
    assert connector.helper.connector_logger.info.call_count == 3
    connector.helper.connector_logger.info.assert_has_calls(
        [
            call("Connector last run: never"),
            call("Connector successfully ran"),
        ]
    )


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_process_data_last_run(
    mocker: MockerFixture, mocked_helper: MockerFixture
) -> None:
    now = datetime.fromisoformat("2025-04-17T15:24:00Z")
    yesterday = datetime.fromisoformat("2025-04-16T15:24:00Z")

    # Only test _process_data method
    collect_intelligence = mocker.patch.object(Connector, "_collect_intelligence")

    connector = Connector(helper=mocked_helper, config=ConnectorSettings())

    # 1 No last_run in state
    connector._process_data()
    collect_intelligence.assert_called_once_with(None, "work-id")
    mocked_helper.set_state.assert_called_once_with({"last_run": now.isoformat()})

    # 2 last_run in state as timestamp (retro compatibility)
    mocked_helper.get_state.return_value = {"last_run": yesterday.timestamp()}
    connector._process_data()
    collect_intelligence.assert_called_with(yesterday, "work-id")
    mocked_helper.set_state.assert_called_with({"last_run": now.isoformat()})

    # 3 last_run in state as ISO format
    mocked_helper.get_state.return_value = {"last_run": yesterday.isoformat()}
    connector._process_data()
    collect_intelligence.assert_called_with(yesterday, "work-id")
    mocked_helper.set_state.assert_called_with({"last_run": now.isoformat()})
