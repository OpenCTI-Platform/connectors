"""Tests for the wiring of the settings into the cvelistV5 connector."""

from datetime import datetime, timedelta, timezone
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


def _connector_for_run(monkeypatch, import_history: bool, state: dict | None):
    """Build a connector whose helper and git handler are mocks."""
    monkeypatch.setattr(main, "CVEProcessor", MagicMock())

    class Settings(StubConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {},
                    "cvelistv5": {"import_history": import_history},
                }
            )

    monkeypatch.setattr(main, "ConnectorSettings", Settings)
    connector = main.CVEListV5Connector()
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = state
    connector.helper.api.work.initiate_work.return_value = "work-id"

    git_handler = MagicMock()
    git_handler.last_run_time = None
    git_handler.get_updated_files.return_value = ["/tmp/a.json", "/tmp/b.json"]
    monkeypatch.setattr(main, "GitHandler", MagicMock(return_value=git_handler))
    return connector, git_handler


def test_import_history_defaults_to_true(monkeypatch, mock_opencti_connector_helper):
    monkeypatch.setattr(main, "ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr(main, "CVEProcessor", MagicMock())

    connector = main.CVEListV5Connector()

    assert connector.import_history is True


def test_no_state_and_import_history_false_skips_the_catch_up(
    monkeypatch, mock_opencti_connector_helper
):
    connector, git_handler = _connector_for_run(monkeypatch, False, None)

    connector._process_updates()

    git_handler.pull_updates.assert_called_once()
    git_handler.get_updated_files.assert_not_called()
    connector.cve_processor.process_cve_file.assert_not_called()
    git_handler.update_last_run_time.assert_called_once()
    state = connector.helper.set_state.call_args.args[0]
    assert state["last_run_processed"] == 0
    assert state["last_run_failed"] == 0
    assert state["initial_import_skipped"] is True
    last_run = datetime.fromisoformat(state["last_run"])
    assert last_run.tzinfo == timezone.utc
    work_args = connector.helper.api.work.to_processed.call_args
    assert work_args.args[0] == "work-id"
    assert "Initial catch-up skipped by configuration" in work_args.args[1]
    assert work_args.kwargs.get("in_error") is not True


def test_no_state_and_import_history_true_imports_the_full_list(
    monkeypatch, mock_opencti_connector_helper
):
    connector, git_handler = _connector_for_run(monkeypatch, True, None)

    connector._process_updates()

    git_handler.get_updated_files.assert_called_once_with(connector.start_year)
    assert connector.cve_processor.process_cve_file.call_count == 2
    state = connector.helper.set_state.call_args.args[0]
    assert state["last_run_processed"] == 2
    assert "initial_import_skipped" not in state


@pytest.mark.parametrize("import_history", [True, False])
def test_existing_state_stays_incremental_whatever_the_setting(
    monkeypatch, mock_opencti_connector_helper, import_history
):
    last_run = "2026-11-01T00:00:00+00:00"
    connector, git_handler = _connector_for_run(
        monkeypatch, import_history, {"last_run": last_run}
    )

    connector._process_updates()

    assert git_handler.last_run_time == datetime.fromisoformat(last_run)
    git_handler.get_updated_files.assert_called_once_with(connector.start_year)
    assert connector.cve_processor.process_cve_file.call_count == 2
    state = connector.helper.set_state.call_args.args[0]
    assert "initial_import_skipped" not in state
