import json
import os
from pathlib import Path

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()

        self.helper = OpenCTIConnectorHelper(self.load)

        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
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
        self.recommended_actions = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RECOMMENDED_ACTIONS",
            ["microsoft_defender_intel_synchronizer", "recommended_actions"],
            self.load,
            default="",
        )
        rbac_group_names_raw = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_RBAC_GROUP_NAMES",
            ["microsoft_defender_intel_synchronizer", "rbac_group_names"],
            self.load,
            default="[]",
        )
        if isinstance(rbac_group_names_raw, str):
            try:
                self.rbac_group_names = json.loads(rbac_group_names_raw)
                if not isinstance(self.rbac_group_names, list):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                self.helper.log_warning(
                    "Warning: rbac_group_names is not a valid JSON array."
                    " Using empty list."
                )
                self.rbac_group_names = []
        elif isinstance(rbac_group_names_raw, list):
            self.rbac_group_names = rbac_group_names_raw
        else:
            self.rbac_group_names = []
        self.educate_url = get_config_variable(
            "MICROSOFT_DEFENDER_INTEL_SYNCHRONIZER_EDUCATE_URL",
            ["microsoft_defender_intel_synchronizer", "educate_url"],
            self.load,
            default="",
        )
