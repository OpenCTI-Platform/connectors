import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        self.load = self._load_config()
        self._initialize_configuration()

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

    def _initialize_configuration(self) -> None:
        """
        Connector configuration variables
        """
        self.chronicle_project_id = get_config_variable(
            "CHRONICLE_PROJECT_ID",
            ["chronicle", "project_id"],
            self.load,
            False,
            None,
            True,
        )
        self.chronicle_project_instance = get_config_variable(
            "CHRONICLE_PROJECT_INSTANCE",
            ["chronicle", "project_instance"],
            self.load,
            False,
            True,
        )
        self.chronicle_project_region = get_config_variable(
            "CHRONICLE_PROJECT_REGION",
            ["chronicle", "project_region"],
            self.load,
            False,
            True,
        )
        self.chronicle_private_key_id = get_config_variable(
            "CHRONICLE_PRIVATE_KEY_ID",
            ["chronicle", "private_key_id"],
            self.load,
            False,
            True,
        )
        self.chronicle_private_key = get_config_variable(
            "CHRONICLE_PRIVATE_KEY",
            ["chronicle", "private_key"],
            self.load,
            False,
            True,
        )
        self.chronicle_client_email = get_config_variable(
            "CHRONICLE_CLIENT_EMAIL",
            ["chronicle", "client_email"],
            self.load,
            False,
            True,
        )
        self.chronicle_client_id = get_config_variable(
            "CHRONICLE_CLIENT_ID",
            ["chronicle", "client_id"],
            self.load,
            False,
            True,
        )
        self.chronicle_auth_uri = get_config_variable(
            "CHRONICLE_AUTH_URI",
            ["chronicle", "auth_uri"],
            self.load,
            False,
            True,
        )
        self.chronicle_token_uri = get_config_variable(
            "CHRONICLE_TOKEN_URI",
            ["chronicle", "token_uri"],
            self.load,
            False,
            True,
        )
        self.chronicle_auth_provider_cert = get_config_variable(
            "CHRONICLE_AUTH_PROVIDER_CERT",
            ["chronicle", "auth_provider_cert"],
            self.load,
            False,
            True,
        )
        self.chronicle_client_cert_url = get_config_variable(
            "CHRONICLE_CLIENT_CERT_URL",
            ["chronicle", "client_cert_url"],
            self.load,
            False,
            True,
        )
