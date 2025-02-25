import os
from pathlib import Path
from typing import Optional, cast

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
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
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
        self.taxii_server_url = cast(
            str,
            get_config_variable(
                "CONNECTOR_IBM_XTI_TAXII_SERVER_URL",
                ["connector_ibm_xti", "taxii_server_url"],
                self.load,
                required=True,
            ),
        )

        self.taxii_user = cast(
            str,
            get_config_variable(
                "CONNECTOR_IBM_XTI_TAXII_USER",
                ["connector_ibm_xti", "taxii_user"],
                self.load,
                required=True,
            ),
        )

        self.taxii_pass = cast(
            str,
            get_config_variable(
                "CONNECTOR_IBM_XTI_TAXII_PASS",
                ["connector_ibm_xti", "taxii_pass"],
                self.load,
                required=True,
            ),
        )

        self.taxii_collections = cast(
            Optional[str],
            get_config_variable(
                "CONNECTOR_IBM_XTI_TAXII_COLLECTIONS",
                ["connector_ibm_xti", "taxii_collections"],
                self.load,
            ),
        )

        self.debug = cast(
            Optional[str],
            get_config_variable(
                "CONNECTOR_IBM_XTI_DEBUG",
                ["connector_ibm_xti", "debug"],
                self.load,
            ),
        )
