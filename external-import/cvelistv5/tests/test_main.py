"""Tests for the wiring of the settings into the cvelistV5 connector."""

from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import main
import pytest
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "1d6c1e5a-3a42-4e43-9b33-6d1b4e1f0e5c",
                    "name": "CVEProject cvelistV5",
                    "scope": "identity,vulnerability,software",
                    "log_level": "error",
                    "duration_period": "PT2H",
                },
                "cvelistv5": {
                    "repo_url": "https://git.example.com/mirror/cvelistV5.git",
                    "repo_branch": "develop",
                    "local_path": "/tmp/cvelistV5",
                    "history_start_year": 2019,
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()

    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "1d6c1e5a-3a42-4e43-9b33-6d1b4e1f0e5c"
    assert helper.connect_name == "CVEProject cvelistV5"
    assert helper.connect_scope == "identity,vulnerability,software"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(monkeypatch, mock_opencti_connector_helper):
    monkeypatch.setattr(main, "ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr(main, "CVEProcessor", MagicMock())

    connector = main.CVEListV5Connector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert connector.helper.connect_id == "1d6c1e5a-3a42-4e43-9b33-6d1b4e1f0e5c"
    assert connector.repo_url == "https://git.example.com/mirror/cvelistV5.git"
    assert connector.repo_branch == "develop"
    assert connector.local_path == "/tmp/cvelistV5"
    assert connector.start_year == 2019
    assert connector.duration_period == timedelta(hours=2)
    main.CVEProcessor.assert_called_once_with(connector.helper)


def test_history_start_year_below_minimum_falls_back(
    monkeypatch, mock_opencti_connector_helper
):
    class OldYearSettings(StubConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "cvelistv5": {"history_start_year": 1990},
                }
            )

    monkeypatch.setattr(main, "ConnectorSettings", OldYearSettings)
    monkeypatch.setattr(main, "CVEProcessor", MagicMock())

    connector = main.CVEListV5Connector()

    assert connector.start_year == main.DEFAULT_START_YEAR


def test_start_schedules_with_duration_period(
    monkeypatch, mock_opencti_connector_helper
):
    monkeypatch.setattr(main, "ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr(main, "CVEProcessor", MagicMock())
    connector = main.CVEListV5Connector()
    connector.helper = MagicMock()

    connector.start()

    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector._process_updates,
        duration_period=7200.0,
    )
