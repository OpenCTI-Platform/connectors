import pytest
from export_report_pdf.config import ConnectorConfig
from export_report_pdf.connector import Connector
from pycti import OpenCTIConnectorHelper


@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_config(mocked_helper: OpenCTIConnectorHelper) -> None:
    connector = Connector(config=ConnectorConfig(), helper=mocked_helper)
    assert connector.config.company_address_line_1 == "Company Address Line 1"
    assert connector.config.company_address_line_2 == "Company Address Line 2"
    assert connector.config.company_address_line_3 == "Company Address Line 3"
    assert connector.config.company_email == "export-report-pdf@email.com"
    assert connector.config.company_phone_number == "+1-234-567-8900"
    assert connector.config.company_website == "https://export-report-pdf.com"
    assert connector.config.defang_urls == True
    assert connector.config.indicators_only == False
    assert connector.config.primary_color == "#ff8c00"
    assert connector.config.secondary_color == "#000000"


@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_start(mocked_helper: OpenCTIConnectorHelper) -> None:
    connector = Connector(config=ConnectorConfig(), helper=mocked_helper)
    connector.run()
    mocked_helper.listen.assert_called_once()
