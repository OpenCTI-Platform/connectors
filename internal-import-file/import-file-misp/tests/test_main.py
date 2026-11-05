import importlib.util
import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

# The connector entry module keeps its historical hyphenated file name
# (`import-file-misp.py`), which is not importable through the regular import
# system. It is therefore loaded from its file location.
_MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "import-file-misp.py"
)
_spec = importlib.util.spec_from_file_location("import_file_misp", _MODULE_PATH)
import_file_misp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(import_file_misp)
MispImportFile = import_file_misp.MispImportFile


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


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of ConnectorSettings for testing purpose.
    Overrides _load_config_dict to return a fake but valid config dict.
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
                    "name": "ImportFileMISP",
                    "scope": "application/json",
                    "log_level": "error",
                    "validate_before_import": True,
                    "auto": False,
                },
                "misp_import_file": {
                    "create_reports": True,
                    "report_type": "misp-event",
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": False,
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": False,
                    "author_from_tags": False,
                    "markings_from_tags": False,
                    "import_to_ids_no_score": 40,
                    "import_unsupported_observables_as_text": False,
                    "import_unsupported_observables_as_text_transparent": True,
                    "import_with_attachments": False,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that ConnectorSettings can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from BaseConnectorSettings)
        - the method `to_helper_config` MUST return a dict
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that OpenCTIConnectorHelper can be instantiated successfully:
        - the value of settings.to_helper_config MUST be the expected dict for OpenCTIConnectorHelper
        - the helper MUST be able to get its instance's attributes from the config dict
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ImportFileMISP"
    assert helper.connect_scope == "application/json"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST build its config through ConnectorSettings
        - the connector's main class MUST be able to access pycti API through self.helper
    """
    monkeypatch.setattr(import_file_misp, "ConnectorSettings", StubConnectorSettings)

    connector = MispImportFile()

    assert isinstance(connector.config, ConnectorSettings)
    assert connector.helper is not None
    # The connector still exposes its historical config attributes.
    assert connector.misp_import_file_create_indicators is True
    assert connector.misp_import_file_import_to_ids_no_score == 40
