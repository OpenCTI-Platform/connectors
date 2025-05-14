"""Models"""

from pathlib import Path
from typing import Any

import yaml
from pycti import get_config_variable

__all__ = [
    "ConfigConnector",
]


class ConfigConnector:
    def __init__(self) -> None:
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict[str, Any]:
        config_file_path = Path(__file__).parent.parent.joinpath("config.yml")
        return (
            yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
            if config_file_path.is_file()
            else {}
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
