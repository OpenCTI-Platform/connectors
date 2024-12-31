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
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.load,
            required=True,
        )

        # Connector extra parameters
        self.harfanglab_api_base_url = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_URL",
            yaml_path=["harfanglab_incidents", "url"],
            config=self.load,
            required=True,
        )
        self.harfanglab_ssl_verify = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_SSL_VERIFY",
            yaml_path=["harfanglab_incidents", "ssl_verify"],
            config=self.load,
            isNumber=False,
            required=True,
        )

        self.harfanglab_token = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_TOKEN",
            yaml_path=["harfanglab_incidents", "token"],
            config=self.load,
            required=True,
        )

        self.harfanglab_import_threats = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_IMPORT_THREATS",
            yaml_path=["harfanglab_incidents", "import_threats"],
            config=self.load,
            isNumber=False,
            default=False,
        )
        self.harfanglab_alert_statuses = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_ALERT_STATUSES",
            yaml_path=["harfanglab_incidents", "alert_statuses"],
            config=self.load,
            required=True,
        )
        self.harfanglab_alert_types = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_ALERT_TYPES",
            yaml_path=["harfanglab_incidents", "alert_types"],
            config=self.load,
            required=True,
        )
        self.harfanglab_default_marking = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_DEFAULT_MARKING",
            yaml_path=["harfanglab_incidents", "default_marking"],
            config=self.load,
            isNumber=False,
            default="TLP:CLEAR",
        )
        self.harfanglab_default_score = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_DEFAULT_SCORE",
            yaml_path=["harfanglab_incidents", "default_score"],
            config=self.load,
        )
        harfanglab_import_start_date_var = get_config_variable(
            env_var="HARFANGLAB_INCIDENTS_IMPORT_START_DATE",
            yaml_path=["harfanglab_incidents", "import_start_date"],
            config=self.load,
        )
        self.harfanglab_import_start_datetime = (
            parser.parse(harfanglab_import_start_date_var).replace(tzinfo=tz.UTC)
            if harfanglab_import_start_date_var
            else EPOCH_DATETIME
        )
