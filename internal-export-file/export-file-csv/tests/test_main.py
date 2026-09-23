"""Tests for the manager-supported wiring of the export-file-csv connector.

The connector module file name is hyphenated (`export-file-csv.py`) and is not
importable as a normal package, so it is loaded by path via importlib.
"""

import importlib.util
import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "export-file-csv.py")
)
_spec = importlib.util.spec_from_file_location("export_file_csv", _SRC)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Could not load export-file-csv module from {_SRC}")
export_file_csv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_file_csv)
ExportFileCsv = export_file_csv.ExportFileCsv


class StubConnectorSettings(ConnectorSettings):
    """Subclass of ``ConnectorSettings`` returning a fake but valid config dict."""

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
                    "name": "ExportFileCsv",
                    "scope": "text/csv",
                    "log_level": "error",
                },
                "export_file_csv": {
                    "delimiter": ";",
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper (API calls to OpenCTI)."""

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

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ExportFileCsv"
    assert helper.connect_scope == "text/csv"
    assert helper.connect_type == "INTERNAL_EXPORT_FILE"


def test_connector_is_instantiated(monkeypatch, mock_opencti_connector_helper):
    monkeypatch.setattr(export_file_csv, "ConnectorSettings", StubConnectorSettings)

    connector = ExportFileCsv()

    assert isinstance(connector.config, ConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.export_file_csv_delimiter == ";"
    assert connector.errors == []


def test_connector_uses_configured_delimiter(
    monkeypatch, mock_opencti_connector_helper
):
    """The CSV delimiter is read from the validated Pydantic settings."""

    class CommaDelimiterSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {"id": "connector-id"},
                    "export_file_csv": {"delimiter": ","},
                }
            )

    monkeypatch.setattr(export_file_csv, "ConnectorSettings", CommaDelimiterSettings)

    connector = ExportFileCsv()

    assert connector.export_file_csv_delimiter == ","
    csv_output = connector.export_dict_list_to_csv([{"name": "foo", "value": "bar"}])
    assert csv_output.splitlines()[0] == '"name","value"'
