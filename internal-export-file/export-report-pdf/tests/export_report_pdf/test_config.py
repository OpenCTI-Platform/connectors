from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from export_report_pdf.settings import ConnectorSettings


def test_config_should_load_from_environment(mock_config, config_dict) -> None:
    """
    Test that ConnectorSettings loads all the connector's variables from the environment.
    """
    config = ConnectorSettings()

    assert str(config.opencti.url) == "http://localhost:8080/"
    assert config.opencti.token.get_secret_value() == "opencti-token"
    assert config.connector.id == "export-report-pdf-connector-id"
    assert config.connector.name == "ExportReportPdf"
    assert config.connector.scope == ["application/pdf"]
    assert config.connector.type == "INTERNAL_EXPORT_FILE"
    assert config.export_report_pdf.company_address_line_1 == "Company Address Line 1"
    assert config.export_report_pdf.company_address_line_2 == "Company Address Line 2"
    assert config.export_report_pdf.company_address_line_3 == "Company Address Line 3"
    assert config.export_report_pdf.company_email == "export-report-pdf@email.com"
    assert config.export_report_pdf.company_phone_number == "+1-234-567-8900"
    assert config.export_report_pdf.company_website == "https://export-report-pdf.com"
    assert config.export_report_pdf.defang_urls is True
    assert config.export_report_pdf.indicators_only is False
    assert config.export_report_pdf.primary_color == "#ff8c00"
    assert config.export_report_pdf.secondary_color == "#000000"


def test_config_should_apply_defaults() -> None:
    """
    Test that ConnectorSettings falls back on the connector's default values
    when only the required variables are set.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {"id": "connector-id"},
                    "export_report_pdf": {},
                }
            )

    config = FakeConnectorSettings()

    assert config.connector.name == "ExportReportPdf"
    assert config.connector.scope == ["application/pdf"]
    assert config.connector.log_level == "error"
    assert config.export_report_pdf.primary_color == "#ff8c00"
    assert config.export_report_pdf.secondary_color == "#000000"
    assert config.export_report_pdf.company_address_line_1 is None
    assert config.export_report_pdf.company_address_line_2 is None
    assert config.export_report_pdf.company_address_line_3 is None
    assert config.export_report_pdf.company_phone_number is None
    assert config.export_report_pdf.company_email is None
    assert config.export_report_pdf.company_website is None
    assert config.export_report_pdf.indicators_only is False
    assert config.export_report_pdf.defang_urls is False


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
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
                    "defang_urls": True,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"id": "connector-id"},
                "export_report_pdf": {},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict) -> None:
    """
    Test that ConnectorSettings accepts valid input.
    _load_config_dict is overridden to return a fake but valid dict.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.export_report_pdf, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {"id": "connector-id"},
                "export_report_pdf": {},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"id": 42},
                "export_report_pdf": {},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"id": "connector-id"},
                "export_report_pdf": {"indicators_only": "not-a-boolean"},
            },
            "export_report_pdf.indicators_only",
            id="invalid_indicators_only",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name) -> None:
    """
    Test that ConnectorSettings raises on invalid input.
    _load_config_dict is overridden to return a fake and invalid dict.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)
