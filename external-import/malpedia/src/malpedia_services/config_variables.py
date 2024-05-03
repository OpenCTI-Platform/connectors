import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class MalpediaConfig:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config():
        """
        Instantiate the connector helper from config
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        return config

    def _initialize_configurations(self):
        """
        Extra config
        """
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
        )

        self.auth_key = get_config_variable(
            "MALPEDIA_AUTH_KEY",
            ["malpedia", "auth_key"],
            self.load,
        )

        self.interval_sec = get_config_variable(
            "MALPEDIA_INTERVAL_SEC",
            ["malpedia", "interval_sec"],
            self.load,
            isNumber=True,
        )

        self.import_intrusion_sets = get_config_variable(
            "MALPEDIA_IMPORT_INTRUSION_SETS",
            ["malpedia", "import_intrusion_sets"],
            self.load,
        )

        self.import_yara = get_config_variable(
            "MALPEDIA_IMPORT_YARA",
            ["malpedia", "import_yara"],
            self.load,
        )

        self.create_indicators = get_config_variable(
            "MALPEDIA_CREATE_INDICATORS", ["malpedia", "create_indicators"], self.load
        )

        self.create_observables = get_config_variable(
            "MALPEDIA_CREATE_OBSERVABLES",
            ["malpedia", "create_observables"],
            self.load,
        )
