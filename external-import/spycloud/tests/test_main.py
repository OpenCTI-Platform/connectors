import runpy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from spycloud_connector import SpyCloudConnector
from spycloud_connector.services import ConverterToStix, SpycloudClient
from spycloud_connector.settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "SpyCloud",
                    "scope": "spycloud",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "spycloud": {
                    "api_base_url": "https://api.spycloud.io/enterprise-v2",
                    "api_key": "test-api-key",
                    "severity_levels": "20,25",
                    "watchlist_types": "domain,subdomain",
                    "tlp_level": "amber+strict",
                    "import_start_date": "2024-01-01T00:00:00Z",
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully.
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully
    with the connector settings converted by `to_helper_config()`.
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "SpyCloud"
    assert helper.connect_scope == "spycloud"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the existing connector class builds its settings and its helper
    from `ConnectorSettings` and injects them in its client and converter.
    """
    monkeypatch.setattr(
        "spycloud_connector.connector.ConnectorSettings", StubConnectorSettings
    )

    connector = SpyCloudConnector()

    assert isinstance(connector.config, ConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"

    assert connector.config.spycloud.api_base_url == (
        "https://api.spycloud.io/enterprise-v2/"
    )
    assert connector.config.spycloud.severity_levels == [20, 25]
    assert connector.config.spycloud.watchlist_types == ["domain", "subdomain"]
    assert connector.config.spycloud.import_start_date == datetime(
        2024, 1, 1, tzinfo=UTC
    )

    assert isinstance(connector.client, SpycloudClient)
    assert connector.client.session.headers["X-API-KEY"] == "test-api-key"

    assert isinstance(connector.converter_to_stix, ConverterToStix)
    assert connector.converter_to_stix.author.name == "SpyCloud"
    assert connector.converter_to_stix.tlp_marking.level == "amber+strict"


def test_connector_should_schedule_with_duration_period(
    mock_opencti_connector_helper, monkeypatch
):
    """
    Test that the connector schedules its process every `CONNECTOR_DURATION_PERIOD`.
    """
    monkeypatch.setattr(
        "spycloud_connector.connector.ConnectorSettings", StubConnectorSettings
    )

    connector = SpyCloudConnector()
    connector.helper.schedule_process = MagicMock()
    connector.run()

    assert connector.config.connector.duration_period == timedelta(minutes=5)
    connector.helper.schedule_process.assert_called_once_with(
        connector.process_message, 300
    )


def test_main_should_print_the_startup_error_and_exit(monkeypatch, capsys):
    """A startup error MUST be printed with its traceback, and the process MUST exit with 1."""
    for env_var in (
        "OPENCTI_URL",
        "OPENCTI_TOKEN",
        "SPYCLOUD_API_BASE_URL",
        "SPYCLOUD_API_KEY",
    ):
        monkeypatch.delenv(env_var, raising=False)

    main_path = Path(__file__).parent.parent / "main.py"
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(main_path), run_name="__main__")

    assert exit_info.value.code == 1
    stderr = capsys.readouterr().err
    assert "Traceback" in stderr
    assert "Error validating configuration" in stderr
