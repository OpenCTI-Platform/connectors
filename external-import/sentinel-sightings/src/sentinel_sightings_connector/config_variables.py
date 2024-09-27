import os
from pathlib import Path

import yaml
from pycti import get_config_variable


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
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.tenant_id = get_config_variable(
            "TENANT_ID", ["sentinel", "tenant_id"], self.load
        )
        self.client_id = get_config_variable(
            "CLIENT_ID", ["sentinel", "client_id"], self.load
        )
        self.client_secret = get_config_variable(
            "CLIENT_SECRET", ["sentinel", "client_secret"], self.load
        )
        self.login_url = get_config_variable(
            "LOGIN_URL", ["sentinel", "login_url"], self.load
        )
        self.api_base_url = get_config_variable(
            "API_BASE_URL", ["sentinel", "api_base_url"], self.load
        )
        self.request_path = get_config_variable(
            "REQUEST_PATH", ["sentinel", "request_path"], self.load
        )
        self.incident_path = get_config_variable(
            "INCIDENT_PATH", ["sentinel", "incident_path"], self.load
        )
        self.confidence_level = get_config_variable(
            "CONFIDENCE_LEVEL", ["sentinel", "confidence_level"], self.load
        )
        self.target_product = get_config_variable(
            "TARGET_PRODUCT", ["sentinel", "target_product"], self.load
        )
