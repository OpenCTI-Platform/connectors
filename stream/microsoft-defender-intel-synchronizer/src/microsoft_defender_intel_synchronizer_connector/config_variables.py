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
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TENANT_ID",
            ["microsoft_defender_intel_synchronizer", "tenant_id"],
            self.load,
        )
        self.client_id = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_ID",
            ["microsoft_defender_intel_synchronizer", "client_id"],
            self.load,
        )
        self.client_secret = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_CLIENT_SECRET",
            ["microsoft_defender_intel_synchronizer", "client_secret"],
            self.load,
        )
        self.login_url = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_LOGIN_URL",
            ["microsoft_defender_intel_synchronizer", "login_url"],
            self.load,
            default="https://login.microsoft.com",
        )
        self.base_url = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_BASE_URL",
            ["microsoft_defender_intel_synchronizer", "base_url"],
            self.load,
            default="https://api.securitycenter.microsoft.com",
        )
        self.resource_path = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RESOURCE_PATH",
            ["microsoft_defender_intel_synchronizer", "resource_path"],
            self.load,
            default="/api/indicators",
        )
        self.expire_time = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EXPIRE_TIME",
            ["microsoft_defender_intel_synchronizer", "expire_time"],
            self.load,
            isNumber=True,
            default=30,
        )
        self.action = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_ACTION",
            ["microsoft_defender_intel_synchronizer", "action"],
            self.load,
        )
        self.passive_only = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_PASSIVE_ONLY",
            ["microsoft_defender_intel_synchronizer", "passive_only"],
            self.load,
            default=False,
        )
        self.taxii_collections = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_TAXII_COLLECTIONS",
            ["microsoft_defender_intel_synchronizer", "taxii_collections"],
            self.load,
        ).split(",")
        self.interval = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_INTERVAL",
            ["microsoft_defender_intel_synchronizer", "interval"],
            self.load,
            isNumber=True,
            default=300,
        )
