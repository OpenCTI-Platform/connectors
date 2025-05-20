import datetime
import os
from pathlib import Path

import isodate
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
            default="PT1H",
        )
        self.acti_username = get_config_variable(
            "ACCENTURE_ACTI_USERNAME",
            ["accenture_acti", "username"],
            self.load,
            required=True,
        )
        self.acti_password = get_config_variable(
            "ACCENTURE_ACTI_PASSWORD",
            ["accenture_acti", "password"],
            self.load,
            required=True,
        )
        self.acti_user_pool_id = get_config_variable(
            "ACCENTURE_ACTI_USER_POOL_ID",
            ["accenture_acti", "user_pool_id"],
            self.load,
            required=True,
        )
        self.acti_client_id = get_config_variable(
            "ACCENTURE_ACTI_CLIENT_ID",
            ["accenture_acti", "client_id"],
            self.load,
            required=True,
        )
        self.tlp_level = get_config_variable(
            "ACCENTURE_ACTI_CLIENT_TLP_LEVEL",
            ["accenture_acti", "tlp_level"],
            self.load,
            default="amber+strict",
        )
        self.relative_import_start_date = get_config_variable(
            "ACCENTURE_ACTI_RELATIVE_IMPORT_START_DATE",
            ["accenture_acti", "relative_import_start_date"],
            self.load,
            default=datetime.timedelta(days=30),
        )
        if type(self.relative_import_start_date) == str:
            self.relative_import_start_date = isodate.parse_duration(
                self.relative_import_start_date
            )
