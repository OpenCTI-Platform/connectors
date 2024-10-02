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

        # Connector extra parameters
        self.tenant_id = get_config_variable(
            "SENTINEL_STREAM_TENANT_ID", ["sentinel_stream", "tenant_id"], self.load
        )
        self.client_id = get_config_variable(
            "SENTINEL_STREAM_CLIENT_ID", ["sentinel_stream", "client_id"], self.load
        )
        self.client_secret = get_config_variable(
            "SENTINEL_STREAM_CLIENT_SECRET",
            ["sentinel_stream", "client_secret"],
            self.load,
        )
        self.login_url = get_config_variable(
            "SENTINEL_STREAM_LOGIN_URL", ["sentinel_stream", "login_url"], self.load
        )
        self.resource_url = get_config_variable(
            "SENTINEL_STREAM_RESOURCE_URL",
            ["sentinel_stream", "resource_url"],
            self.load,
        )
        self.request_url = get_config_variable(
            "SENTINEL_STREAM_REQUEST_URL", ["sentinel_stream", "request_url"], self.load
        )
        self.expire_time = get_config_variable(
            "SENTINEL_STREAM_EXPIRE_TIME", ["sentinel_stream", "expire_time"], self.load
        )
        self.target_product = get_config_variable(
            "SENTINEL_STREAM_TARGET_PRODUCT",
            ["sentinel_stream", "target_product"],
            self.load,
        )
        self.action = get_config_variable(
            "ACTION", ["sentinel_stream", "action"], self.load
        )
        self.tlp_level = get_config_variable(
            "SENTINEL_STREAM_TLP_LEVEL", ["sentinel_stream", "tlp_level"], self.load
        )
        self.passive_only = get_config_variable(
            "SENTINEL_STREAM_PASSIVE_ONLY",
            ["sentinel_stream", "passive_only"],
            self.load,
        )
