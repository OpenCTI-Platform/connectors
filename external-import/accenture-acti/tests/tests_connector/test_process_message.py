import datetime
from unittest.mock import MagicMock

import pytest
from accenture_connector import ConnectorAccenture
from connectors_sdk import Criticity, ProviderApiAuthenticationError


@pytest.fixture
def connector() -> ConnectorAccenture:
    """A connector whose last run was a minute ago: one interval to collect."""
    helper = MagicMock()
    last_run = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(minutes=1)
    helper.get_state.return_value = {
        "last_run": last_run.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    connector = ConnectorAccenture(config=MagicMock(), helper=helper)
    connector.client = MagicMock()
    return connector


def test_process_message_returns_no_error_when_the_run_succeeds(connector):
    connector.client.get_reports.return_value = {"objects": []}

    assert connector.process_message() is None


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
