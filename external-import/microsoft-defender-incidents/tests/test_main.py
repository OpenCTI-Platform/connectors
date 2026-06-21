import os
import runpy
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector import ConnectorSettings, MicrosoftDefenderIncidentsConnector
from pycti import OpenCTIConnectorHelper

_MAIN_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "main.py")
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
                    "id": "c4d8a1e2-3f5b-4c9d-8e7a-1b2c3d4e5f6a",
                    "name": "Microsoft Defender Incidents",
                    "scope": "defender",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "microsoft_defender_incidents": {
                    "tenant_id": "test-tenant-id",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "import_start_date": "2025-01-01T00:00:00Z",
                    "api_base_url": "https://graph.microsoft.com/v1.0",
                    "incident_path": "/security/incidents",
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated
    successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid
        any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "c4d8a1e2-3f5b-4c9d-8e7a-1b2c3d4e5f6a"
    assert helper.connect_name == "Microsoft Defender Incidents"
    assert helper.connect_scope == "defender"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT1H"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid
        any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = MicrosoftDefenderIncidentsConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


# ---------------------------------------------------------------------------
# main.py entry point
# ---------------------------------------------------------------------------


def test_main_entry_point_success():
    """main.py bootstraps settings, helper, connector and calls run()."""
    mock_connector = MagicMock()

    with (
        patch("connector.ConnectorSettings") as mock_settings_cls,
        patch("connector.MicrosoftDefenderIncidentsConnector") as mock_connector_cls,
        patch("pycti.OpenCTIConnectorHelper"),
    ):
        mock_connector_cls.return_value = mock_connector
        mock_settings_cls.return_value.to_helper_config.return_value = {}
        runpy.run_path(_MAIN_PATH, run_name="__main__")

    mock_connector.run.assert_called_once()


def test_main_entry_point_exception_exits_with_code_1():
    """main.py catches exceptions and exits with code 1."""
    with patch("connector.ConnectorSettings", side_effect=ValueError("bad config")):
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(_MAIN_PATH, run_name="__main__")

    assert exc_info.value.code == 1
