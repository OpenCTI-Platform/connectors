import datetime
from unittest.mock import MagicMock, create_autospec

import pytest
from accenture_connector import ConnectorAccenture
from connectors_sdk import (
    Criticity,
    DataConversionError,
    ErrorStore,
    ProviderApiAuthenticationError,
)
from pycti.utils.opencti_logger import logger


@pytest.fixture(autouse=True)
def empty_error_store():
    """ErrorStore is a singleton: each test ends with an empty store."""
    yield
    ErrorStore().clear()


@pytest.fixture
def connector() -> ConnectorAccenture:
    """A connector whose last run was a minute ago: one interval to collect."""
    helper = MagicMock()
    # A plain MagicMock accepts any argument: the autospec rejects, like pycti does,
    # the calls that do not match the logger's signature (e.g. exc_info=True)
    helper.connector_logger = create_autospec(
        logger("ERROR")("test-connector"), instance=True
    )
    last_run = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(minutes=1)
    helper.get_state.return_value = {
        "last_run": last_run.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    connector = ConnectorAccenture(config=MagicMock(), helper=helper)
    connector.client = MagicMock()
    return connector


def test_process_message_returns_no_error_when_the_run_succeeds(connector):
    connector.client.get_reports.return_value = {"objects": []}

    assert connector.process_message() == []


def test_process_message_does_not_report_the_previous_run_errors(connector):
    ErrorStore().record_error(DataConversionError("from the previous run"))
    connector.client.get_reports.return_value = {"objects": []}

    assert connector.process_message() == []


def test_process_message_returns_the_skipped_items(connector):
    def process_bundle(bundle):
        ErrorStore().record_error(DataConversionError("bad image"))
        return bundle

    connector.client.get_reports.return_value = {"objects": [{"id": "report--1"}]}
    connector._process_bundle = process_bundle
    connector._send_bundle = MagicMock()

    errors = connector.process_message()

    assert errors == [
        {
            "code": "data.conversion",
            "message": "bad image",
            "criticity": int(Criticity.WARNING),
        }
    ]
    connector._send_bundle.assert_called_once()


def test_process_message_returns_the_run_error_then_the_skipped_items(connector):
    def get_reports(since, until):
        ErrorStore().record_error(DataConversionError("bad image"))
        raise ProviderApiAuthenticationError("bad credentials")

    connector.client.get_reports.side_effect = get_reports

    errors = connector.process_message()

    assert [error["code"] for error in errors] == [
        "api.authentication",
        "data.conversion",
    ]


def test_process_message_does_not_report_the_previous_run_errors_on_failure(
    connector,
):
    ErrorStore().record_error(DataConversionError("from the previous run"))
    connector.client.get_reports.side_effect = ProviderApiAuthenticationError(
        "bad credentials"
    )

    errors = connector.process_message()

    assert [error["code"] for error in errors] == ["api.authentication"]


def test_process_message_returns_the_connector_error(connector):
    connector.client.get_reports.side_effect = ProviderApiAuthenticationError(
        "bad credentials"
    )

    errors = connector.process_message()

    assert errors == [
        {
            "code": "api.authentication",
            "message": "bad credentials",
            "criticity": int(Criticity.CRITICAL),
        }
    ]
    connector.helper.connector_logger.error.assert_called_once_with(
        "[ERROR] Connector failed: bad credentials"
    )


def test_process_message_returns_an_unknown_error_for_other_exceptions(connector):
    connector.client.get_reports.side_effect = RuntimeError("boom")

    errors = connector.process_message()

    assert errors == [
        {
            "code": "other.unknown",
            "message": "boom",
            "criticity": int(Criticity.CRITICAL),
        }
    ]
    connector.helper.connector_logger.error.assert_called_once_with(
        "[ERROR] Connector failed: boom"
    )
