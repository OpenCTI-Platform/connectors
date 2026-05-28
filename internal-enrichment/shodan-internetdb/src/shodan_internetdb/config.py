"""Models"""

from pathlib import Path
from typing import Any

import yaml
from pycti import get_config_variable

__all__ = [
    "ConfigConnector",
]

TLP_MARKING_OPTIONS = [
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:RED",
    "TLP:CLEAR",
    "TLP:AMBER+STRICT",
]


class ConfigConnector:
    def __init__(self) -> None:
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()
        self._check_configuration()

    @staticmethod
    def _load_config() -> dict[str, Any]:
        config_file_path = Path(__file__).parent.parent.joinpath("config.yml")
        return (
            yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
            if config_file_path.is_file()
            else {}
        )

    def _check_configuration(self) -> None:
        """
        Run configuration additional checks not handled by get_config_variables function.
        """
        if self.shodan_max_tlp not in TLP_MARKING_OPTIONS:
            raise ValueError(
                "Incorrect value for configuration parameter 'max_tlp'. "
                f"Permitted values are: {', '.join(TLP_MARKING_OPTIONS)}"
            )

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.shodan_max_tlp = get_config_variable(
            "SHODAN_MAX_TLP",
            ["shodan", "max_tlp"],
            self.load,
            default="TLP:WHITE",
        )

        self.shodan_ssl_verify = get_config_variable(
            "SHODAN_SSL_VERIFY",
            ["shodan", "ssl_verify"],
            self.load,
            default=True,
        )
