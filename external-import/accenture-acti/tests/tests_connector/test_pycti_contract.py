"""Run the decorated callback through pycti's own run function, not a mock of it.

The other tests mock the helper: they would still pass if pycti stopped reporting
the list returned by the callback. These tests call the real
``OpenCTIConnectorHelper._run_and_collect_errors`` used by ``schedule_iso``, with a
real ``ConnectorInfo``, so they fail if that contract changes.
"""

import datetime
from unittest.mock import MagicMock, create_autospec

import pytest
from accenture_connector import ConnectorAccenture
from connectors_sdk import Criticity, ErrorStore, ProviderApiAuthenticationError
from pycti import OpenCTIConnectorHelper
from pycti.connector.opencti_connector_helper import ConnectorInfo
from pycti.utils.opencti_logger import logger


@pytest.fixture(autouse=True)
def empty_error_store():
    """ErrorStore is a singleton: each test starts and ends with an empty store."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


@pytest.fixture
def connector() -> ConnectorAccenture:
    """A connector whose helper keeps a real ConnectorInfo."""
    helper = MagicMock()
    helper.connector_logger = create_autospec(
        logger("ERROR")("test-connector"), instance=True
    )
    helper.connector_info = ConnectorInfo(logger=helper.connector_logger)
    last_run = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(minutes=1)
    helper.get_state.return_value = {
        "last_run": last_run.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    connector = ConnectorAccenture(config=MagicMock(), helper=helper)
    connector.client = MagicMock()
    return connector


def _run(connector: ConnectorAccenture) -> None:
    """Run the connector once, as pycti's schedule_iso does."""
    OpenCTIConnectorHelper._run_and_collect_errors(
        connector.helper, connector.process_message
    )


def test_pycti_reports_the_error_that_stopped_the_run(connector):
    connector.client.get_reports.side_effect = ProviderApiAuthenticationError(
        "bad credentials"
    )

    _run(connector)  # no exception escapes

    assert connector.helper.connector_info.errors == [
        {
            "code": "api.authentication",
            "message": "bad credentials",
            "criticity": int(Criticity.CRITICAL),
        }
    ]


def test_pycti_reports_no_error_after_a_successful_run(connector):
    connector.client.get_reports.side_effect = ProviderApiAuthenticationError(
        "bad credentials"
    )
    _run(connector)
    connector.client.get_reports.side_effect = None
    connector.client.get_reports.return_value = {"objects": []}

    _run(connector)

    assert connector.helper.connector_info.errors == []
