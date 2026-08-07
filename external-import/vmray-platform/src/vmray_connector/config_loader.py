"""
Config File
"""

from pathlib import Path

from pycti import get_config_variable
from yaml import safe_load


class ConfigConnector:
    """
    Loads and initializes configuration settings for the VMRay connector.
    Handles reading from a YAML config file and environment variables.
    """

    def __init__(self) -> None:
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
        if config_file_path.is_file():
            with open(config_file_path, encoding="utf-8") as f:
                config = safe_load(f) or {}
        else:
            config = {}
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
        self.vmray_base_url = get_config_variable(
            "VMRAY_SERVER",
            ["vmray", "server"],
            self.load,
        )
        self.vmray_api_key = get_config_variable(
            "VMRAY_API_KEY",
            ["vmray", "api_key"],
            self.load,
        )
        self.sample_verdict = get_config_variable(
            "VMRAY_SAMPLE_VERDICT",
            ["vmray", "sample_verdict"],
            self.load,
        )
        self.iocs_verdict = get_config_variable(
            "VMRAY_IOCS_VERDICT",
            ["vmray", "iocs_verdict"],
            self.load,
        )
        self.initial_fetch_date = get_config_variable(
            "VMRAY_INITIAL_FETCH_DATE",
            ["vmray", "initial_fetch_date"],
            self.load,
        )
        self.default_tlp = get_config_variable(
            "VMRAY_DEFAULT_TLP",
            ["vmray", "default_tlp"],
            self.load,
        )
        self.classifications_color = get_config_variable(
            "VMRAY_MALICIO",
            ["vmray", "classifications_color"],
            self.load,
        )
        self.threat_names_color = get_config_variable(
            "VMRAY_THREAT_NAMES_COLOR",
            ["vmray", "threat_names_color"],
            self.load,
        )
        self.vti_color = get_config_variable(
            "VMRAY_VTI_COLOR",
            ["vmray", "vti_color"],
            self.load,
        )
        self.mitre_color = get_config_variable(
            "VMRAY_MITRE_COLOR",
            ["vmray", "mitre_color"],
            self.load,
        )
