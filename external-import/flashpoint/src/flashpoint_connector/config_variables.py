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

        # required false to support previous interval configuration option
        self.duration_period = get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.load,
            required=False,
        )

        self.api_key = get_config_variable(
            "FLASHPOINT_API_KEY",
            ["flashpoint", "api_key"],
            self.load,
        )

        self.import_start_date = get_config_variable(
            "FLASHPOINT_IMPORT_START_DATE",
            ["flashpoint", "import_start_date"],
            self.load,
        )

        self.import_reports = get_config_variable(
            "FLASHPOINT_IMPORT_REPORTS",
            ["flashpoint", "import_reports"],
            self.load,
            default=True,
        )

        self.indicators_in_reports = get_config_variable(
            "FLASHPOINT_INDICATORS_IN_REPORTS",
            ["flashpoint", "indicators_in_reports"],
            self.load,
            default=False,
        )

        self.import_indicators = get_config_variable(
            "FLASHPOINT_IMPORT_INDICATORS",
            ["flashpoint", "import_indicators"],
            self.load,
            default=True,
        )

        self.import_alerts = get_config_variable(
            "FLASHPOINT_IMPORT_ALERTS",
            ["flashpoint", "import_alerts"],
            self.load,
            default=True,
        )

        self.alert_create_related_entities = get_config_variable(
            "FLASHPOINT_ALERT_CREATE_RELATED_ENTITIES",
            ["flashpoint", "alert_create_related_entities"],
            self.load,
            default=False,
        )

        self.import_communities = get_config_variable(
            "FLASHPOINT_IMPORT_COMMUNITIES",
            ["flashpoint", "import_communities"],
            self.load,
            default=False,
        )

        communities_queries = get_config_variable(
            "FLASHPOINT_COMMUNITIES_QUERIES",
            ["flashpoint", "communities_queries"],
            self.load,
            default="cybersecurity,cyberattack",
        )
        self.communities_queries = [x.strip() for x in communities_queries.split(",")]

        self.import_communities = get_config_variable(
            "FLASHPOINT_ALERTS_CREATE_RELATED_ENTITIES",
            ["flashpoint", "alerts_create_related_entities"],
            self.load,
            default=False,
        )

        # deprecated configuration option, use duration_period instead
        self.flashpoint_interval: int = get_config_variable(
            "FLASHPOINT_INTERVAL",
            ["flashpoint", "interval"],
            self.load,
            isNumber=True,
            default=5,
        )
