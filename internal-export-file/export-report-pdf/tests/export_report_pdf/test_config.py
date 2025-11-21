from export_report_pdf.config import ConnectorConfig


def test_config(mock_config, config_dict):
    config = ConnectorConfig()
    assert config.company_address_line_1 == "Company Address Line 1"
    assert config.company_address_line_2 == "Company Address Line 2"
    assert config.company_address_line_3 == "Company Address Line 3"
    assert config.company_email == "export-report-pdf@email.com"
    assert config.company_phone_number == "+1-234-567-8900"
    assert config.company_website == "https://export-report-pdf.com"
    assert config.defang_urls == True
    assert config.indicators_only == False
    assert config.primary_color == "#ff8c00"
    assert config.secondary_color == "#000000"
