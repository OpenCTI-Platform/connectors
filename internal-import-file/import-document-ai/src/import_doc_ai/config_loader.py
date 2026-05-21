"""
See https://github.com/OpenCTI-Platform/connectors/blob/42e0ad002318224e88cac2b4796c0bc136a4aa75/templates/internal-import-file/src/internal_import_file_connector/config_loader.py
"""

import base64
import os
from pathlib import Path

import yaml

from .util import get_config_variable_legacy


class ConfigConnector:
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
        # Connector extra parameters

        self.api_base_url = get_config_variable_legacy(
            ["IMPORT_DOCUMENT_AI_API_BASE_URL", "CONNECTOR_WEB_SERVICE_URL"],
            [["import_document_ai", "api_base_url"], ["connector", "web_service_url"]],
            self.load,
            required=True,
        )

        self.api_key = get_config_variable_legacy(
            ["IMPORT_DOCUMENT_AI_API_KEY", "CONNECTOR_LICENCE_KEY_PEM"],
            [["import_document_ai", "api_key"], ["connector", "licence_key_pem"]],
            self.load,
            required=True,
        )
        self.licence_key_base64 = base64.b64encode(self.api_key.encode())

        # Read connector flags from config (create_indicator, web_service_url, etc.)
        self.create_indicator = get_config_variable_legacy(
            ["IMPORT_DOCUMENT_AI_CREATE_INDICATOR", "IMPORT_DOCUMENT_CREATE_INDICATOR"],
            [
                ["import_document_ai", "create_indicator"],
                ["import_document", "create_indicator"],
            ],
            self.load,
            default=False,
        )

        self.include_relationships = get_config_variable_legacy(
            [
                "IMPORT_DOCUMENT_AI_INCLUDE_RELATIONSHIPS",
                "IMPORT_DOCUMENT_INCLUDE_RELATIONSHIPS",
            ],
            [
                ["import_document_ai", "include_relationships"],
                ["import_document", "include_relationships"],
            ],
            self.load,
            default=True,
        )
