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

        # read and update the max timestamp of last processed entry
        self.last_processed_entry_old = 0
        self.last_processed_entry_new = 0
        # implementing a primitive caching
        self.threat_cache = {}

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
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
        )

        self.interval = get_config_variable(
            "URLHAUS_INTERVAL",
            ["urlhaus", "interval"],
            self.load,
            isNumber=True,
            default=3,
            required=True,
        )

        # Connector extra parameters
        self.urlhaus_csv_url = get_config_variable(
            "URLHAUS_CSV_URL",
            ["urlhaus", "csv_url"],
            self.load,
        )

        self.default_x_opencti_score = get_config_variable(
            "URLHAUS_DEFAULT_X_OPENCTI_SCORE",
            ["urlhaus", "default_x_opencti_score"],
            config=self.load,
            isNumber=True,
            default=80,
            required=False,
        )

        self.urlhaus_import_offline = get_config_variable(
            "URLHAUS_IMPORT_OFFLINE",
            ["urlhaus", "import_offline"],
            self.load,
            False,
            True,
        )

        self.threats_from_labels = get_config_variable(
            "URLHAUS_THREATS_FROM_LABELS",
            ["urlhaus", "threats_from_labels"],
            self.load,
            False,
            True,
        )
