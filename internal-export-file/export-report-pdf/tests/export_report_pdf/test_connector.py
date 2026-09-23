import pytest
from export_report_pdf.connector import Connector
from export_report_pdf.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_config(mocked_helper: OpenCTIConnectorHelper) -> None:
    connector = Connector(config=ConnectorSettings(), helper=mocked_helper)
    config = connector.config.export_report_pdf
    assert config.company_address_line_1 == "Company Address Line 1"
    assert config.company_address_line_2 == "Company Address Line 2"
    assert config.company_address_line_3 == "Company Address Line 3"
    assert config.company_email == "export-report-pdf@email.com"
    assert config.company_phone_number == "+1-234-567-8900"
    assert config.company_website == "https://export-report-pdf.com"
    assert config.defang_urls is True
    assert config.indicators_only is False
    assert config.primary_color == "#ff8c00"
    assert config.secondary_color == "#000000"


@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_start(mocked_helper: OpenCTIConnectorHelper) -> None:
    connector = Connector(config=ConnectorSettings(), helper=mocked_helper)
    connector.run()
    mocked_helper.listen.assert_called_once()
