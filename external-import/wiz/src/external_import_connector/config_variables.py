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
        self.threat_actor_to_intrusion_set = get_config_variable(
            "WIZ_THREAT_ACTOR_AS_INTRUSION_SET",
            ["wiz", "threat_actor_as_intrusion_set"],
            self.load,
            default=False,
        )
        self.tlp_level = get_config_variable(
            "WIZ_TLP_LEVEL",
            ["wiz", "tlp_level"],
            self.load,
            default="clear",
        )
