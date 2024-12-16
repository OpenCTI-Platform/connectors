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
            "SECOPS_SIEM_PROJECT_ID",
            ["secops_siem", "project_id"],
            self.load,
            False,
            None,
            True,
        )
        self.chronicle_project_instance = get_config_variable(
            "SECOPS_SIEM_PROJECT_INSTANCE",
            ["secops_siem", "project_instance"],
            self.load,
            False,
            True,
        )
        self.chronicle_project_region = get_config_variable(
            "SECOPS_SIEM_PROJECT_REGION",
            ["secops_siem", "project_region"],
            self.load,
            False,
            True,
        )
        self.chronicle_private_key_id = get_config_variable(
            "SECOPS_SIEM_PRIVATE_KEY_ID",
            ["secops_siem", "private_key_id"],
            self.load,
            False,
            True,
        )
        self.chronicle_private_key = get_config_variable(
            "SECOPS_SIEM_PRIVATE_KEY",
            ["secops_siem", "private_key"],
            self.load,
            False,
            True,
        )
        self.chronicle_client_email = get_config_variable(
            "SECOPS_SIEM_CLIENT_EMAIL",
            ["secops_siem", "client_email"],
            self.load,
            False,
            True,
        )
        self.chronicle_client_id = get_config_variable(
            "SECOPS_SIEM_CLIENT_ID",
            ["secops_siem", "client_id"],
            self.load,
            False,
            True,
        )
        self.chronicle_auth_uri = get_config_variable(
            "SECOPS_SIEM_AUTH_URI",
            ["secops_siem", "auth_uri"],
            self.load,
            False,
            True,
        )
        self.chronicle_token_uri = get_config_variable(
            "SECOPS_SIEM_TOKEN_URI",
            ["secops_siem", "token_uri"],
            self.load,
            False,
            True,
        )
        self.chronicle_auth_provider_cert = get_config_variable(
            "SECOPS_SIEM_AUTH_PROVIDER_CERT",
            ["secops_siem", "auth_provider_cert"],
            self.load,
            False,
            True,
        )
        self.chronicle_client_cert_url = get_config_variable(
            "SECOPS_SIEM_CLIENT_CERT_URL",
            ["secops_siem", "client_cert_url"],
            self.load,
            False,
            True,
        )
