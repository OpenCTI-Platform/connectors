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
            "SENTINEL_SIGHTINGS_TENANT_ID",
            ["sentinel_sightings", "tenant_id"],
            self.load,
        )
        self.client_id = get_config_variable(
            "SENTINEL_SIGHTINGS_CLIENT_ID",
            ["sentinel_sightings", "client_id"],
            self.load,
        )
        self.client_secret = get_config_variable(
            "SENTINEL_SIGHTINGS_CLIENT_SECRET",
            ["sentinel_sightings", "client_secret"],
            self.load,
        )
        self.login_url = get_config_variable(
            "SENTINEL_SIGHTINGS_LOGIN_URL",
            ["sentinel_sightings", "login_url"],
            self.load,
        )
        self.api_base_url = get_config_variable(
            "SENTINEL_SIGHTINGS_API_BASE_URL",
            ["sentinel_sightings", "api_base_url"],
            self.load,
        )
        self.incident_path = get_config_variable(
            "SENTINEL_SIGHTINGS_INCIDENT_PATH",
            ["sentinel_sightings", "incident_path"],
            self.load,
        )
        self.confidence_level = get_config_variable(
            "SENTINEL_SIGHTINGS_CONFIDENCE_LEVEL",
            ["sentinel_sightings", "confidence_level"],
            self.load,
        )
        self.target_product = get_config_variable(
            "SENTINEL_SIGHTINGS_TARGET_PRODUCT",
            ["sentinel_sightings", "target_product"],
            self.load,
        )
