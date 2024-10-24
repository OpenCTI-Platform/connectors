import os
from datetime import datetime
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
    def prepare_iso_format(date: str) -> str | datetime:
        try:
            if len(date) == 10:
                prepared_date = datetime.strptime(date, "%Y-%m-%d").strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            elif len(date) == 20:
                prepared_date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            else:
                default_date = "2020-01-01T00:00:00Z"
                return default_date
            return prepared_date
        except ValueError:
            default_date = "2020-01-01T00:00:00Z"
            return default_date

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
            "SENTINEL_INCIDENTS_TENANT_ID",
            ["sentinel_incidents", "tenant_id"],
            self.load,
        )
        self.client_id = get_config_variable(
            "SENTINEL_INCIDENTS_CLIENT_ID",
            ["sentinel_incidents", "client_id"],
            self.load,
        )
        self.client_secret = get_config_variable(
            "SENTINEL_INCIDENTS_CLIENT_SECRET",
            ["sentinel_incidents", "client_secret"],
            self.load,
        )
        self.login_url = get_config_variable(
            "SENTINEL_INCIDENTS_LOGIN_URL",
            ["sentinel_incidents", "login_url"],
            self.load,
        )
        self.api_base_url = get_config_variable(
            "SENTINEL_INCIDENTS_API_BASE_URL",
            ["sentinel_incidents", "api_base_url"],
            self.load,
        )
        self.incident_path = get_config_variable(
            "SENTINEL_INCIDENTS_INCIDENT_PATH",
            ["sentinel_incidents", "incident_path"],
            self.load,
        )
        self.confidence_level = get_config_variable(
            "SENTINEL_INCIDENTS_CONFIDENCE_LEVEL",
            ["sentinel_incidents", "confidence_level"],
            self.load,
        )
        self.target_product = get_config_variable(
            "SENTINEL_INCIDENTS_TARGET_PRODUCT",
            ["sentinel_incidents", "target_product"],
            self.load,
        )
        sentinel_import_start_date_var = get_config_variable(
            "SENTINEL_INCIDENTS_IMPORT_START_DATE",
            ["sentinel_incidents", "import_start_date"],
            self.load,
        )
        self.import_start_date = self.prepare_iso_format(sentinel_import_start_date_var)
