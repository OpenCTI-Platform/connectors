import datetime
from unittest.mock import MagicMock, create_autospec

import pytest
from accenture_connector import ConnectorAccenture
from connectors_sdk import ErrorStore
from pycti.utils.opencti_logger import logger

BUNDLE = {"type": "bundle", "objects": [{"id": "report--1"}]}


@pytest.fixture(autouse=True)
def empty_error_store():
    """ErrorStore is a singleton: each test starts and ends with an empty store."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


@pytest.fixture
def connector() -> ConnectorAccenture:
    """A connector whose bundle sending fails."""
    helper = MagicMock()
    # The autospec rejects the calls that do not match the pycti logger's signature
    helper.connector_logger = create_autospec(
        logger("ERROR")("test-connector"), instance=True
    )
    helper.api.work.initiate_work.return_value = "work-1"
    helper.send_stix2_bundle.side_effect = ConnectionError("queue unreachable")
    return ConnectorAccenture(config=MagicMock(), helper=helper)


def test_a_failed_send_closes_the_work_in_error_and_raises(connector):
    with pytest.raises(ConnectionError, match="queue unreachable"):
        connector._send_bundle(0, BUNDLE)

    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Failed to send the bundle: ConnectionError", in_error=True
    )


def test_a_failed_close_does_not_hide_the_send_error(connector):
    connector.helper.api.work.to_processed.side_effect = RuntimeError("API down")

    with pytest.raises(ConnectionError, match="queue unreachable"):
        connector._send_bundle(0, BUNDLE)

    connector.helper.connector_logger.error.assert_called_once_with(
        "[CONNECTOR] Failed to close the work in error",
        {
            "work_id": "work-1",
            "error": "queue unreachable",
            "close_error": "API down",
        },
    )


def test_a_successful_send_closes_the_work_without_error(connector):
    connector.helper.send_stix2_bundle.side_effect = None
    connector.helper.send_stix2_bundle.return_value = ["bundle"]

    assert connector._send_bundle(0, BUNDLE) == ["bundle"]

    work_id, _message = connector.helper.api.work.to_processed.call_args.args
    assert work_id == "work-1"
    assert "in_error" not in connector.helper.api.work.to_processed.call_args.kwargs


def test_a_failed_send_is_the_error_returned_by_the_run(connector):
    last_run = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(minutes=1)
    connector.helper.get_state.return_value = {
        "last_run": last_run.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    connector.client = MagicMock()
    connector.client.get_reports.return_value = BUNDLE
    connector._process_bundle = lambda bundle: bundle

    errors = connector.process_message()

    assert [(error["code"], error["message"]) for error in errors] == [
        ("other.unknown", "[ConnectionError] queue unreachable")
    ]
    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Failed to send the bundle: ConnectionError", in_error=True
    )
