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
            "MICROSOFT_SENTINEL_INTEL_TENANT_ID",
            ["microsoft_sentinel_intel", "tenant_id"],
            self.load,
        )
        self.client_id = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_CLIENT_ID",
            ["microsoft_sentinel_intel", "client_id"],
            self.load,
        )
        self.client_secret = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_CLIENT_SECRET",
            ["microsoft_sentinel_intel", "client_secret"],
            self.load,
        )
        self.login_url = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_LOGIN_URL",
            ["microsoft_sentinel_intel", "login_url"],
            self.load,
            default="https://login.microsoft.com",
        )
        self.base_url = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_BASE_URL",
            ["microsoft_sentinel_intel", "base_url"],
            self.load,
            default="https://graph.microsoft.com",
        )
        self.resource_path = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_RESOURCE_PATH",
            ["microsoft_sentinel_intel", "resource_path"],
            self.load,
            default="/beta/security/tiIndicators",
        )
        self.expire_time = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_EXPIRE_TIME",
            ["microsoft_sentinel_intel", "expire_time"],
            self.load,
            isNumber=True,
            default=30,
        )
        self.target_product = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_TARGET_PRODUCT",
            ["microsoft_sentinel_intel", "target_product"],
            self.load,
        )
        self.action = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_ACTION",
            ["microsoft_sentinel_intel", "action"],
            self.load,
        )
        self.tlp_level = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_TLP_LEVEL",
            ["microsoft_sentinel_intel", "tlp_level"],
            self.load,
        )
        self.passive_only = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_PASSIVE_ONLY",
            ["microsoft_sentinel_intel", "passive_only"],
            self.load,
            default=False,
        )
