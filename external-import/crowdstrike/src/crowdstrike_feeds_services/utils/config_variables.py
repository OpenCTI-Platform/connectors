import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigCrowdstrike:
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
        config_file_path = Path(__file__).parents[2].joinpath("config.yml")
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
        self.update_existing_data: bool = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
        )

        # Crowdstrike configurations

        self.base_url: str = get_config_variable(
            "CROWDSTRIKE_API_BASE_URL",
            ["crowdstrike", "base_url"],
            self.load,
            default="https://api.crowdstrike.com",
        )

        self.client_id: str = get_config_variable(
            "CROWDSTRIKE_CLIENT_ID",
            ["crowdstrike", "client_id"],
            self.load,
            default="CHANGEME",
        )

        self.client_secret: str = get_config_variable(
            "CROWDSTRIKE_CLIENT_SECRET",
            ["crowdstrike", "client_secret"],
            self.load,
            default="CHANGEME",
        )

        self.tlp: str = get_config_variable(
            "CROWDSTRIKE_TLP",
            ["crowdstrike", "tlp"],
            self.load,
            default="Amber",
        )

        self.create_observables: bool = get_config_variable(
            "CROWDSTRIKE_CREATE_OBSERVABLES",
            ["crowdstrike", "create_observables"],
            self.load,
        )

        self.create_indicators: bool = get_config_variable(
            "CROWDSTRIKE_CREATE_INDICATORS",
            ["crowdstrike", "create_indicators"],
            self.load,
        )

        self.scopes: str = get_config_variable(
            "CROWDSTRIKE_SCOPES",
            ["crowdstrike", "scopes"],
            self.load,
        )

        self.actor_start_timestamp: int = get_config_variable(
            "CROWDSTRIKE_ACTOR_START_TIMESTAMP",
            ["crowdstrike", "actor_start_timestamp"],
            self.load,
            isNumber=True,
        )

        self.report_start_timestamp: int = get_config_variable(
            "CROWDSTRIKE_REPORT_START_TIMESTAMP",
            ["crowdstrike", "report_start_timestamp"],
            self.load,
            isNumber=True,
        )

        self.report_status: str = get_config_variable(
            "CROWDSTRIKE_REPORT_STATUS",
            ["crowdstrike", "report_status"],
            self.load,
        )

        self.report_include_types: str = get_config_variable(
            "CROWDSTRIKE_REPORT_INCLUDE_TYPES",
            ["crowdstrike", "report_include_types"],
            self.load,
        )

        self.report_type: str = get_config_variable(
            "CROWDSTRIKE_REPORT_TYPE",
            ["crowdstrike", "report_type"],
            self.load,
        )

        self.report_guess_malware: bool = get_config_variable(
            "CROWDSTRIKE_REPORT_GUESS_MALWARE",
            ["crowdstrike", "report_guess_malware"],
            self.load,
        )

        self.indicator_start_timestamp: int = get_config_variable(
            "CROWDSTRIKE_INDICATOR_START_TIMESTAMP",
            ["crowdstrike", "indicator_start_timestamp"],
            self.load,
            isNumber=True,
        )

        self.indicator_exclude_types: str = get_config_variable(
            "CROWDSTRIKE_INDICATOR_EXCLUDE_TYPES",
            ["crowdstrike", "indicator_exclude_types"],
            self.load,
        )

        self.indicator_low_score: int = get_config_variable(
            "CROWDSTRIKE_INDICATOR_LOW_SCORE",
            ["crowdstrike", "indicator_low_score"],
            self.load,
            isNumber=True,
        )

        self.indicator_low_score_labels: str = get_config_variable(
            "CROWDSTRIKE_INDICATOR_LOW_SCORE_LABELS",
            ["crowdstrike", "indicator_low_score_labels"],
            self.load,
        )

        self.indicator_unwanted_labels: str = get_config_variable(
            "CROWDSTRIKE_INDICATOR_UNWANTED_LABELS",
            ["crowdstrike", "indicator_unwanted_labels"],
            self.load,
        )
        if self.indicator_unwanted_labels is not None:
            self.indicator_unwanted_labels = self.indicator_unwanted_labels.lower()

        self.interval_sec: int = get_config_variable(
            "CROWDSTRIKE_INTERVAL_SEC",
            ["crowdstrike", "interval_sec"],
            self.load,
            isNumber=True,
        )
