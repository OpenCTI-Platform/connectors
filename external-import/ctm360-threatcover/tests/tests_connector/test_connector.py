from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, Ctm360ThreatcoverConnector
from ctm360_threatcover_client import Ctm360ThreatcoverAPIError
from pycti import OpenCTIConnectorHelper

INDICATOR = {
    "type": "indicator",
    "id": "indicator--11111111-1111-4111-8111-111111111111",
    "created": "2024-05-01T00:00:00.000Z",
    "pattern": "[ipv4-addr:value='1.2.3.4']",
    "pattern_type": "stix",
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
                    "scope": "ctm360-threatcover",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "ctm360_threatcover": {
                    "discovery_url": "https://taxii.example.com/taxii2/",
                    "collection": "observables",
                    "token": "test-api-token",
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

    instance = Ctm360ThreatcoverConnector(config=settings, helper=helper)
    instance.client = MagicMock()
    return instance


def test_collect_intelligence_returns_objects(connector):
    connector.client.get_objects.return_value = [INDICATOR]

    objects = connector._collect_intelligence(added_after=None)
    types = [o["type"] for o in objects]

    assert "indicator" in types
    assert "identity" in types  # author appended
    assert connector.client.get_objects.call_args.kwargs["added_after"] is None


def test_collect_intelligence_empty(connector):
    connector.client.get_objects.return_value = []
    assert connector._collect_intelligence(added_after=None) == []


def test_process_message_sends_bundle_and_updates_state(connector):
    connector.client.get_objects.return_value = [INDICATOR]

    connector.process_message()

    connector.helper.send_stix2_bundle.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()
    saved_state = connector.helper.set_state.call_args[0][0]
    assert "added_after" in saved_state


def test_process_message_passes_added_after_from_state(connector):
    connector.helper.get_state = MagicMock(
        return_value={"added_after": "2024-01-01T00:00:00.000Z"}
    )
    connector.client.get_objects.return_value = []

    connector.process_message()

    assert (
        connector.client.get_objects.call_args.kwargs["added_after"]
        == "2024-01-01T00:00:00.000Z"
    )


def test_process_message_skips_work_when_no_data(connector):
    connector.client.get_objects.return_value = []

    connector.process_message()

    # No data: no work is initiated (avoids empty jobs), but state still advances.
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()
    connector.helper.set_state.assert_called_once()


def test_process_message_handles_api_error(connector):
    connector.client.get_objects.side_effect = Ctm360ThreatcoverAPIError("boom")

    connector.process_message()  # must not raise

    connector.helper.connector_logger.error.assert_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    # State must NOT advance on error (so the next run retries instead of skipping).
    connector.helper.set_state.assert_not_called()
    # The error happened before any work was initiated, so there is nothing to close.
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()


def test_process_message_closes_work_in_error_when_send_fails(connector):
    connector.client.get_objects.return_value = [INDICATOR]
    connector.helper.send_stix2_bundle.side_effect = RuntimeError("send failed")

    connector.process_message()  # must not raise

    connector.helper.connector_logger.error.assert_called()
    # State must NOT advance on error (so the next run retries instead of skipping).
    connector.helper.set_state.assert_not_called()
    # The work item was initiated and must be closed as failed, not left running.
    connector.helper.api.work.to_processed.assert_called_once()
    assert (
        connector.helper.api.work.to_processed.call_args.kwargs.get("in_error") is True
    )


def test_run_schedules_process(connector):
    connector.run()
    connector.helper.schedule_process.assert_called_once()
