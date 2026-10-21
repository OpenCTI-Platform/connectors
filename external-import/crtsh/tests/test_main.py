import runpy
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from crtsh import CrtSHClient
from main import CrtshConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


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
                    "name": "crt.sh",
                    "scope": "crtsh",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "crtsh": {
                    "domain": "example.com",
                    "labels": "crtsh,osint",
                    "marking_refs": "TLP:WHITE",
                    "is_expired": True,
                    "is_wildcard": False,
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
    assert helper.connect_name == "crt.sh"
    assert helper.connect_scope == "crtsh"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the existing connector class builds its settings and its helper
    from `ConnectorSettings` and consumes the configured values.
    """
    monkeypatch.setattr("lib.external_import.ConnectorSettings", StubConnectorSettings)

    connector = CrtshConnector()

    assert isinstance(connector.config, ConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.interval == 3600
    assert connector._get_interval() == 3600
    assert connector.domain == "example.com"
    assert connector.labels == ["crtsh", "osint"]
    assert connector.marking_refs == "TLP:WHITE"
    assert connector.is_expired is True
    assert connector.is_wildcard is False
    assert isinstance(connector.api, CrtSHClient)
    assert connector.api.url.endswith("&exclude=expired")


def test_main_should_print_the_startup_error_and_exit(monkeypatch, capsys):
    """A startup error MUST be printed with its traceback, and the process MUST exit with 1."""
    for env_var in ("OPENCTI_URL", "OPENCTI_TOKEN", "CRTSH_DOMAIN"):
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.setattr("time.sleep", lambda _: None)

    main_path = Path(__file__).parent.parent / "src" / "main.py"
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(main_path), run_name="__main__")

    assert exit_info.value.code == 1
    stderr = capsys.readouterr().err
    assert "Traceback" in stderr
    assert "Error validating configuration" in stderr


def test_connector_should_not_mark_objects_when_marking_refs_is_unset(
    mock_opencti_connector_helper, monkeypatch
):
    """Without `CRTSH_MARKING_REFS`, the imported objects MUST have no marking (as before)."""

    class UnmarkedConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "crtsh": {"domain": "example.com"},
                }
            )

    monkeypatch.setattr(
        "lib.external_import.ConnectorSettings", UnmarkedConnectorSettings
    )

    connector = CrtshConnector()

    assert connector.marking_refs is None
    assert connector.api.marking_refs is None
