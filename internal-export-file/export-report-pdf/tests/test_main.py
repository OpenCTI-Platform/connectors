from typing import Any
from unittest.mock import MagicMock

import pytest
from export_report_pdf.connector import Connector
from export_report_pdf.settings import ConnectorSettings
from main import main
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture


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
                    "name": "ExportReportPdf",
                    "scope": "application/pdf",
                    "log_level": "error",
                },
                "export_report_pdf": {
                    "primary_color": "#ff8c00",
                    "secondary_color": "#000000",
                    "company_address_line_1": "Example Name",
                    "company_address_line_2": "123 Main Street",
                    "company_address_line_3": "Miami, FL 33101 USA",
                    "company_phone_number": "888.888.8888",
                    "company_email": "intelligence_reports@example.com",
                    "company_website": "https://example.com",
                    "indicators_only": False,
                    "defang_urls": False,
                },
            }
        )


def test_connector_settings_is_instantiated() -> None:
    """
    Test that ConnectorSettings can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from BaseConnectorSettings)
        - the method `to_helper_config` MUST return a dict
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(
    mock_opencti_connector_helper,
) -> None:
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
    assert helper.connect_name == "ExportReportPdf"
    assert helper.connect_scope == "application/pdf"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(
    mock_opencti_connector_helper, mocker: MockerFixture
) -> None:
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through self.config
        - the connector's main class MUST be able to access pycti API through self.helper
    """
    mocker.patch("export_report_pdf.connector.Connector._set_colors")

    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = Connector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


def test_main(mocker: MockerFixture) -> None:
    # Make sure the main starts without errors
    mocker.patch("main.ConnectorSettings", StubConnectorSettings)
    mocker.patch("main.OpenCTIConnectorHelper")
    mocker.patch("export_report_pdf.connector.Connector._set_colors")
    main()
