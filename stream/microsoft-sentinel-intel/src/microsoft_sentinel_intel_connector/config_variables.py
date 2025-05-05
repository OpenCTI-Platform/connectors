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

        self.workspace_id = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_WORKSPACE_ID",
            ["sentinel_intel", "workspace_id"],
            self.load,
        )

        self.source_system = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_SOURCE_SYSTEM",
            ["microsoft_sentinel_intel", "source_system"],
            self.load,
            False,
            "Opencti Stream Connector",
        )

        self.login_type = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_LOGIN_TYPE",
            ["microsoft_sentinel_intel", "login_type"],
            self.load,
            False,
            "client_secret",
        )

        self.resource_group = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_RESOURCE_GROUP",
            ["microsoft_sentinel_intel", "resource_group"],
            self.load,
            False,
        )

        self.subscription_id = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_SUBSCRIPTION_ID",
            ["microsoft_sentinel_intel", "subscription_id"],
            self.load,
            False,
        )

        self.workspace_name = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_WORKSPACE_NAME",
            ["microsoft_sentinel_intel", "workspace_name"],
            self.load,
            False,
        )

        self.delete_extensions = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_DELETE_EXTENSIONS",
            ["microsoft_sentinel_intel", "delete_extensions"],
            self.load,
            False,
            True,
        )

        self.extra_labels = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_EXTRA_LABELS",
            ["microsoft_sentinel_intel", "extra_labels"],
            self.load,
            False,
        )
