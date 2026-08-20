from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, CorelightInvestigatorConnector
from corelight_investigator_client import CorelightInvestigatorAPIError
from pycti import OpenCTIConnectorHelper

ALERT = {
    "alert_id": "a-1",
    "name": "Beaconing detected",
    "EventType": "Detection",
    "severity": 9,
    "timestamp": "2024-05-01T00:00:00Z",
    "src_ip": "1.2.3.4",
}


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "corelight-investigator",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "corelight_investigator": {
                    "api_base_url": "https://eu.api.investigator.corelight.com",
                    "api_key": "test-api-key",
                    "tlp_level": "amber",
                },
            }
        )


@pytest.fixture
def connector(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.get_state = MagicMock(return_value={})
    helper.set_state = MagicMock()
    helper.stix2_create_bundle = MagicMock(return_value="bundle")
    helper.send_stix2_bundle = MagicMock()
    helper.api.work.initiate_work = MagicMock(return_value="work-1")
    helper.api.work.to_processed = MagicMock()
    helper.schedule_process = MagicMock()

    instance = CorelightInvestigatorConnector(config=settings, helper=helper)
    instance.client = MagicMock()
    return instance


def test_collect_intelligence_builds_objects(connector):
    connector.client.get_alerts.return_value = [ALERT]

    objects = connector._collect_intelligence(since="2024-01-01T00:00:00.000Z")
    types = [o["type"] for o in objects]

    assert "incident" in types
    assert "ipv4-addr" in types
    assert "identity" in types


def test_collect_intelligence_empty(connector):
    connector.client.get_alerts.return_value = []
    assert connector._collect_intelligence(since="2024-01-01T00:00:00.000Z") == []


def test_process_message_sends_bundle_and_updates_state(connector):
    connector.client.get_alerts.return_value = [ALERT]

    connector.process_message()

    connector.helper.api.work.initiate_work.assert_called_once()
    connector.helper.send_stix2_bundle.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()
    saved_state = connector.helper.set_state.call_args[0][0]
    assert "last_run" in saved_state


def test_process_message_skips_work_when_no_data(connector):
    connector.client.get_alerts.return_value = []

    connector.process_message()

    # no data -> no work is initiated and no bundle is sent, but state advances
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()
    saved_state = connector.helper.set_state.call_args[0][0]
    assert "last_run" in saved_state


def test_process_message_handles_api_error(connector):
    connector.client.get_alerts.side_effect = CorelightInvestigatorAPIError("boom")

    connector.process_message()  # must not raise

    connector.helper.connector_logger.error.assert_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    # the error occurs while collecting data, before any work is initiated,
    # so there is no dangling work to finalize
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()


def test_process_message_handles_unexpected_error(connector):
    connector.client.get_alerts.side_effect = RuntimeError("kaboom")

    connector.process_message()  # must not raise

    connector.helper.connector_logger.error.assert_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()


def test_process_message_finalizes_work_when_send_fails(connector):
    connector.client.get_alerts.return_value = [ALERT]
    connector.helper.send_stix2_bundle.side_effect = RuntimeError("send failed")

    connector.process_message()  # must not raise

    connector.helper.connector_logger.error.assert_called()
    # a work initiated before the failure must be finalized (in error)
    connector.helper.api.work.initiate_work.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()
    assert connector.helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_since_uses_window_when_no_state(connector):
    connector.helper.get_state = MagicMock(return_value={})
    since = connector._since()
    assert since.endswith("Z")


def test_since_uses_last_run_when_present(connector):
    connector.helper.get_state = MagicMock(
        return_value={"last_run": "2024-03-01T00:00:00.000Z"}
    )
    assert connector._since() == "2024-03-01T00:00:00.000Z"


def test_run_schedules_process(connector):
    connector.run()
    connector.helper.schedule_process.assert_called_once()
