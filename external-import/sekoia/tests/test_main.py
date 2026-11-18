import runpy
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from src import ConnectorSettings, SekoiaConnector


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock the heavy parts of OpenCTIConnectorHelper, mainly the calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` with a fixed and valid config dict, for tests."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "test-connector-id",
                    "name": "Test Sekoia",
                    "scope": "indicator,report",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "sekoia": {
                    "api_key": "test-api-key",
                    "base_url": "https://sekoia.test",
                    "collection": "test-collection",
                    "start_date": "2022-01-01",
                    "limit": 100,
                    "create_observables": False,
                    "import_source_list": True,
                    "import_ioc_relationships": False,
                    "confidence_score": 50,
                    "send_confidence": False,
                },
            }
        )


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()

    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "test-connector-id"
    assert helper.connect_name == "Test Sekoia"
    assert helper.connect_scope == "indicator,report"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = SekoiaConnector(settings, helper)

    assert connector.config == settings
    assert connector.helper == helper
    assert connector.duration_period == timedelta(minutes=5)
    assert connector.api_key == "test-api-key"
    assert connector.base_url == "https://sekoia.test"
    assert connector.collection == "test-collection"
    assert connector.start_date == "2022-01-01"
    assert connector.limit == 100
    assert connector.create_observables is False
    assert connector.import_source_list is True
    assert connector.import_ioc_relationships is False
    assert connector.confidence_score == 50
    assert connector.send_confidence is False


def test_main_runs_connector_with_settings(monkeypatch, mock_opencti_connector_helper):
    # Run `python -m src` with the stub settings, and stop before the run loop.
    monkeypatch.setattr("src.ConnectorSettings", StubConnectorSettings)
    run = MagicMock()
    monkeypatch.setattr(SekoiaConnector, "run", run)
    init = MagicMock(return_value=None)
    monkeypatch.setattr(SekoiaConnector, "__init__", init)

    runpy.run_module("src", run_name="__main__")

    settings, helper = init.call_args.args
    assert isinstance(settings, StubConnectorSettings)
    assert isinstance(helper, OpenCTIConnectorHelper)
    assert helper.connect_id == "test-connector-id"
    run.assert_called_once()
