from pathlib import Path
from typing import Any

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
    def _load_config() -> dict[Any, Any]:
        """
        Load the configuration from the YAML file
        Returns:
            (dict[Any, Any]): Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = {}
        if config_file_path.is_file():
            with open(config_file_path, encoding="utf-8") as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables.
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.load,
        )

        # Connector extra parameters
        self.num_threads = get_config_variable(
            env_var="TIO_NUM_THREADS",
            yaml_path=["tenable_vuln_management", "num_thread"],
            config=self.load,
            isNumber=True,
            default=1,
        )

        self.tio_api_base_url = get_config_variable(
            env_var="TIO_API_BASE_URL",
            yaml_path=["tenable_vuln_management", "api_base_url"],
            config=self.load,
            required=True,
        )
        self.tio_api_access_key = get_config_variable(
            env_var="TIO_API_ACCESS_KEY",
            yaml_path=["tenable_vuln_management", "api_access_key"],
            config=self.load,
            required=True,
        )

        self.tio_api_secret_key = get_config_variable(
            env_var="TIO_API_SECRET_KEY",
            yaml_path=["tenable_vuln_management", "api_secret_key"],
            config=self.load,
            required=True,
        )

        self.tio_api_timeout = get_config_variable(
            env_var="TIO_API_TIMEOUT",
            yaml_path=["tenable_vuln_management", "api_timeout"],
            config=self.load,
            required=False,
            isNumber=True,
            default=30,
        )

        # Time to wait in seconds before retrying if HTTPS 429 response.
        self.tio_api_backoff = get_config_variable(
            env_var="TIO_API_BACKOFF",
            yaml_path=["tenable_vuln_management", "api_backoff"],
            config=self.load,
            required=False,
            default=1,
        )

        self.tio_api_retries = get_config_variable(
            env_var="TIO_API_RETRIES",
            yaml_path=["tenable_vuln_management", "api_retries"],
            config=self.load,
            required=False,
            default=5,
        )

        self.tio_export_since = get_config_variable(
            env_var="TIO_EXPORT_SINCE",
            yaml_path=["tenable_vuln_management", "export_since"],
            config=self.load,
            required=False,
            default="1970-01-01T00:00:00+00",
        )

        self.tio_severity_min_level = get_config_variable(
            env_var="TIO_MIN_SEVERITY",
            yaml_path=["tenable_vuln_management", "min_severity"],
            config=self.load,
            required=False,
            default="low",
        )

        self.tio_marking_definition = get_config_variable(
            env_var="TIO_MARKING_DEFINITION",
            yaml_path=["tenable_vuln_management", "marking_definition"],
            config=self.load,
            required=False,
            default="TLP:CLEAR",
        )
