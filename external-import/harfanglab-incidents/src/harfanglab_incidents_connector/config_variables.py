import os
from pathlib import Path

import yaml
from pycti import get_config_variable
from dateutil.parser import parse


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
        self.harfanglab_login = get_config_variable(
            "HARFANGLAB_INCIDENTS_LOGIN", ["harfanglab_incidents", "login"], self.load
        )
        self.harfanglab_password = get_config_variable(
            "HARFANGLAB_INCIDENTS_PASSWORD",
            ["harfanglab_incidents", "password"],
            self.load,
        )

        self.harfanglab_source_list_name = get_config_variable(
            "HARFANGLAB_INCIDENTS_SOURCE_LIST_NAME",
            ["harfanglab_incidents", "source_list_name"],
            self.load,
        )
        self.harfanglab_remove_indicator = get_config_variable(
            "HARFANGLAB_INCIDENTS_REMOVE_INDICATOR",
            ["harfanglab_incidents", "remove_indicator"],
            self.load,
        )
        self.harfanglab_rule_maturity = get_config_variable(
            "HARFANGLAB_INCIDENTS_RULE_MATURITY",
            ["harfanglab_incidents", "rule_maturity"],
            self.load,
        )
        self.harfanglab_import_security_events_as_incidents = get_config_variable(
            "HARFANGLAB_INCIDENTS_IMPORT_SECURITY_EVENTS_AS_INCIDENTS",
            ["harfanglab_incidents", "import_security_events_as_incidents"],
            self.load,
        )
        self.harfanglab_import_threats_as_case_incidents = get_config_variable(
            "HARFANGLAB_INCIDENTS_IMPORT_THREATS_AS_CASE_INCIDENTS",
            ["harfanglab_incidents", "import_threats_as_case_incidents"],
            self.load,
        )
        self.harfanglab_import_security_events_filters_by_status = get_config_variable(
            "HARFANGLAB_INCIDENTS_IMPORT_SECURITY_EVENTS_FILTERS_BY_STATUS",
            ["harfanglab_incidents", "import_security_events_filters_by_status"],
            self.load,
        )
        self.harfanglab_import_filters_by_alert_type = get_config_variable(
            "HARFANGLAB_INCIDENTS_IMPORT_FILTERS_BY_ALERT_TYPE",
            ["harfanglab_incidents", "import_filters_by_alert_type"],
            self.load,
        )
        self.harfanglab_default_markings = get_config_variable(
            "HARFANGLAB_INCIDENTS_DEFAULT_MARKINGS",
            ["harfanglab_incidents", "default_markings"],
            self.load,
        )
        self.harfanglab_source_list = {
            "name": self.harfanglab_source_list_name,
            "description": "Cyber Threat Intelligence knowledge imported from OpenCTI, and any changes must be made only to it.",
            "enabled": True,
        }
        self.harfanglab_default_score = get_config_variable(
            "HARFANGLAB_INCIDENTS_DEFAULT_SCORE",
            ["harfanglab_incidents", "default_score"],
        )
        harfanglab_import_start_date_var = get_config_variable(
            "SENTINEL_INCIDENTS_IMPORT_START_DATE",
            ["sentinel_incidents", "import_start_date"],
            self.load,
        )
        self.harfanglab_import_start_date = (
            parse(harfanglab_import_start_date_var)
            if harfanglab_import_start_date_var
            else None
        )
