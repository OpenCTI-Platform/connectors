import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConnectorConfig:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # ExportReportPdf specific config settings
        self.primary_color = get_config_variable(
            "EXPORT_REPORT_PDF_PRIMARY_COLOR",
            ["export_report_pdf", "primary_color"],
            self.load,
        )
        self.secondary_color = get_config_variable(
            "EXPORT_REPORT_PDF_SECONDARY_COLOR",
            ["export_report_pdf", "secondary_color"],
            self.load,
        )
        self.company_address_line_1 = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_1",
            ["export_report_pdf", "company_address_line_1"],
            self.load,
        )
        self.company_address_line_2 = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_2",
            ["export_report_pdf", "company_address_line_2"],
            self.load,
        )
        self.company_address_line_3 = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_3",
            ["export_report_pdf", "company_address_line_3"],
            self.load,
        )
        self.company_phone_number = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_PHONE_NUMBER",
            ["export_report_pdf", "company_phone_number"],
            self.load,
        )
        self.company_email = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_EMAIL",
            ["export_report_pdf", "company_email"],
            self.load,
        )
        self.company_website = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_WEBSITE",
            ["export_report_pdf", "company_website"],
            self.load,
        )
        self.indicators_only = get_config_variable(
            "EXPORT_REPORT_PDF_INDICATORS_ONLY",
            ["export_report_pdf", "indicators_only"],
            self.load,
        )
        self.defang_urls = get_config_variable(
            "EXPORT_REPORT_PDF_DEFANG_URLS",
            ["export_report_pdf", "defang_urls"],
            self.load,
        )
