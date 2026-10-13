from unittest.mock import MagicMock

import pytest
from connector.connector import StairwellImportConnector
from connector.settings import ConnectorSettings


@pytest.fixture
def connector(monkeypatch):
    for key, value in {
        "OPENCTI_URL": "http://opencti:8080",
        "OPENCTI_TOKEN": "token",
        "CONNECTOR_ID": "22222222-2222-4222-8222-222222222222",
        "CONNECTOR_SCOPE": "stairwell",
        "STAIRWELL_API_TOKEN": "sw-token",
    }.items():
        monkeypatch.setenv(key, value)
    helper = MagicMock()
    helper.api.work.initiate_work.return_value = "work-1"
    return StairwellImportConnector(config=ConnectorSettings(), helper=helper)


def test_successful_run_marks_work_processed(connector):
    connector.runner.run = MagicMock(return_value="2 indicators emitted")
    connector.process_message()
    connector.runner.run.assert_called_once_with(work_id="work-1")
    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1", "2 indicators emitted", in_error=False
    )


def test_failed_run_marks_work_in_error(connector):
    connector.runner.run = MagicMock(side_effect=RuntimeError("boom"))
    connector.process_message()
    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Run failed: boom", in_error=True
    )
