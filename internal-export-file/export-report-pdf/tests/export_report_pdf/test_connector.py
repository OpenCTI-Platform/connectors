import pytest

from export_report_pdf.connector import Connector



@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_config() -> None:
    connector = Connector()
    assert connector.company_address_line_1 == "Company Address Line 1"
    assert connector.company_address_line_2 == "Company Address Line 2"
    assert connector.company_address_line_3 == "Company Address Line 3"
    assert connector.company_email == "export-report-pdf@email.com"
    assert connector.company_phone_number == "+1-234-567-8900"
    assert connector.company_website == "https://export-report-pdf.com"
    assert connector.defang_urls == True
    assert connector.indicators_only == False
    assert connector.primary_color == "#ff8c00"
    assert connector.secondary_color == "#000000"


@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_start() -> None:
    connector = Connector()
    connector.start()
