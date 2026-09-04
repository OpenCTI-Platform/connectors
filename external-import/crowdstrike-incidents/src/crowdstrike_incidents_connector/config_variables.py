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
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.base_url = get_config_variable(
            "CROWDSTRIKE_INCIDENTS_BASE_URL",
            ["crowdstrike_incidents", "base_url"],
            self.load,
        )

        self.client_id = get_config_variable(
            "CROWDSTRIKE_INCIDENTS_CLIENT_ID",
            ["crowdstrike_incidents", "client_id"],
            self.load,
            required=True
        )

        self.client_secret = get_config_variable(
            "CROWDSTRIKE_INCIDENTS_CLIENT_SECRET",
            ["crowdstrike_incidents", "client_secret"],
            self.load,
            required=True
        )

        # Date used as a starting point on the very first run (ISO-8601).
        # Without it, the first run collects every alert of the tenant.
        self.import_start_date = get_config_variable(
            "CROWDSTRIKE_INCIDENTS_IMPORT_START_DATE",
            ["crowdstrike_incidents", "import_start_date"],
            self.load,
        )

        # Optional extra FQL filter applied to the alerts query,
        # e.g. "severity_name:['High','Critical']"
        self.alert_filter = get_config_variable(
            "CROWDSTRIKE_INCIDENTS_ALERT_FILTER",
            ["crowdstrike_incidents", "alert_filter"],
            self.load,
        )

        # Whether previously hidden alerts should be retrieved
        self.alert_include_hidden = get_config_variable(
            "CROWDSTRIKE_INCIDENTS_ALERT_INCLUDE_HIDDEN",
            ["crowdstrike_incidents", "alert_include_hidden"],
            self.load,
            isNumber=False,
            default=False,
        )
