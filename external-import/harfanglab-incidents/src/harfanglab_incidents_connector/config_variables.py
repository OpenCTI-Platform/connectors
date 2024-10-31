import os
from pathlib import Path

import yaml
from dateutil import parser, tz
from pycti import get_config_variable

from .constants import EPOCH_DATETIME


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
        )

        # Connector extra parameters
        self.harfanglab_api_base_url = get_config_variable(
            "HARFANGLAB_INCIDENTS_URL",
            ["harfanglab_incidents", "url"],
            self.load,
        )
        self.harfanglab_ssl_verify = get_config_variable(
            "HARFANGLAB_INCIDENTS_SSL_VERIFY",
            ["harfanglab_incidents", "ssl_verify"],
            self.load,
            False,
            True,
        )
        self.harfanglab_token = get_config_variable(
            "HARFANGLAB_INCIDENTS_TOKEN", ["harfanglab_incidents", "token"], self.load
        )

        self.harfanglab_import_threats = get_config_variable(
            "HARFANGLAB_INCIDENTS_IMPORT_THREATS",
            ["harfanglab_incidents", "import_threats"],
            self.load,
        )
        self.harfanglab_alert_statuses = get_config_variable(
            "HARFANGLAB_INCIDENTS_ALERT_STATUSES",
            ["harfanglab_incidents", "alert_statuses"],
            self.load,
        )
        self.harfanglab_alert_types = get_config_variable(
            "HARFANGLAB_INCIDENTS_ALERT_TYPES",
            ["harfanglab_incidents", "alert_types"],
            self.load,
        )
        self.harfanglab_default_marking = get_config_variable(
            "HARFANGLAB_INCIDENTS_DEFAULT_MARKING",
            ["harfanglab_incidents", "default_marking"],
            self.load,
            False,
            "TLP:CLEAR",
        )
        self.harfanglab_default_score = get_config_variable(
            "HARFANGLAB_INCIDENTS_DEFAULT_SCORE",
            ["harfanglab_incidents", "default_score"],
        )
        harfanglab_import_start_date_var = get_config_variable(
            "HARFANGLAB_INCIDENTS_IMPORT_START_DATE",
            ["harfanglab_incidents", "import_start_date"],
            self.load,
        )
        self.harfanglab_import_start_datetime = (
            parser.parse(harfanglab_import_start_date_var).replace(tzinfo=tz.UTC)
            if harfanglab_import_start_date_var
            else EPOCH_DATETIME
        )
