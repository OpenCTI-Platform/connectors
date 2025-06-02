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

        self.workspace_api_version = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_WORKSPACE_API_VERSION",
            ["microsoft_sentinel_intel", "workspace_api_version"],
            self.load,
            False,
            "2024-02-01-preview",
        )

        self.management_api_version = get_config_variable(
            "MICROSOFT_SENTINEL_INTEL_MANAGEMENT_API_VERSION",
            ["microsoft_sentinel_intel", "management_api_version"],
            self.load,
            False,
            "2025-03-01",
        )

        # Could be deprecated soon
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
