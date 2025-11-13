import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigCrowdstrike:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration fil
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
        self.consumer_count: int = get_config_variable(
            "CONNECTOR_CONSUMER_COUNT",
            ["connector", "consumer_count"],
            self.load,
            isNumber=True,
            default=10,
        )

        # Crowdstrike configurations
        self.api_base_url: str = get_config_variable(
            "CROWDSTRIKE_API_BASE_URL",
            ["crowdstrike", "api_base_url"],
            self.load,
            default="https://api.crowdstrike.com",
        )

        self.client_id: str = get_config_variable(
            "CROWDSTRIKE_CLIENT_ID",
            ["crowdstrike", "client_id"],
            self.load,
            default="CHANGEME",
        )

        self.client_secret: str = get_config_variable(
            "CROWDSTRIKE_CLIENT_SECRET",
            ["crowdstrike", "client_secret"],
            self.load,
            default="CHANGEME",
        )

        self.permanent_delete: str = get_config_variable(
            "CROWDSTRIKE_PERMANENT_DELETE",
            ["crowdstrike", "permanent_delete"],
            self.load,
            default=False,
        )

        self.falcon_for_mobile_active: str = get_config_variable(
            "CROWDSTRIKE_FALCON_FOR_MOBILE_ACTIVE",
            ["crowdstrike", "falcon_for_mobile_active"],
            self.load,
            default=False,
        )

        # Prometheus Metrics configurations
        self.enable_prometheus_metrics: bool = get_config_variable(
            "METRICS_ENABLE", ["metrics", "enable"], self.load, default=False
        )

        self.metrics_port: int = get_config_variable(
            "METRICS_PORT", ["metrics", "port"], self.load, isNumber=True, default=9113
        )

        self.metrics_addr: str = get_config_variable(
            "METRICS_ADDR",
            ["metrics", "addr"],
            self.load,
            default="0.0.0.0",  # no security
        )
